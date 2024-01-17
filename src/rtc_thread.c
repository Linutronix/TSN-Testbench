// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_vlan.h>

#include "config.h"
#include "log.h"
#include "net.h"
#include "rtc_thread.h"
#include "security.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

static void RtcInitializeFrames(unsigned char *frameData, size_t numFrames, const unsigned char *source,
                                const unsigned char *destination)
{
    size_t i;

    for (i = 0; i < numFrames; ++i)
        InitializeProfinetFrame(appConfig.RtcSecurityMode, frameData + i * RTC_TX_FRAME_LENGTH, RTC_TX_FRAME_LENGTH,
                                source, destination, appConfig.RtcPayloadPattern, appConfig.RtcPayloadPatternLength,
                                appConfig.RtcVid | RTC_PCP_VALUE << VLAN_PCP_SHIFT, 0x8000);
}

static void RtcSendFrame(const unsigned char *frameData, size_t frameLength, size_t numFramesPerCycle, int socketFd)
{
    struct ProfinetSecureHeader *srt;
    struct VLANEthernetHeader *eth;
    struct ProfinetRtHeader *rt;
    uint64_t sequenceCounter;
    ssize_t ret;

    if (appConfig.RtcSecurityMode == SECURITY_MODE_NONE)
    {
        /* Fetch meta data */
        rt = (struct ProfinetRtHeader *)(frameData + sizeof(*eth));
        sequenceCounter = MetaDataToSequenceCounter(&rt->MetaData, numFramesPerCycle);
    }
    else
    {
        /* Fetch meta data */
        srt = (struct ProfinetSecureHeader *)(frameData + sizeof(*eth));
        sequenceCounter = MetaDataToSequenceCounter(&srt->MetaData, numFramesPerCycle);
    }

    /* Send it */
    ret = send(socketFd, frameData, frameLength, 0);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtcTx: send() for %" PRIu64 " failed: %s\n", sequenceCounter, strerror(errno));
        return;
    }

    StatRtcFrameSent(sequenceCounter);
}

static void RtcGenAndSendFrame(struct SecurityContext *securityContext, unsigned char *frameData, size_t frameLength,
                               size_t numFramesPerCycle, int socketFd, uint64_t sequenceCounter)
{
    uint32_t metaDataOffset = sizeof(struct VLANEthernetHeader) + offsetof(struct ProfinetRtHeader, MetaData);
    struct PrepareFrameConfig frameConfig;
    ssize_t ret;
    int err;

    frameConfig.Mode = appConfig.RtcSecurityMode;
    frameConfig.SecurityContext = securityContext;
    frameConfig.IvPrefix = (const unsigned char *)appConfig.RtcSecurityIvPrefix;
    frameConfig.PayloadPattern =
        frameData + 1 * RTC_TX_FRAME_LENGTH + sizeof(struct VLANEthernetHeader) + sizeof(struct ProfinetSecureHeader);
    frameConfig.PayloadPatternLength = frameLength - sizeof(struct VLANEthernetHeader) -
                                       sizeof(struct ProfinetSecureHeader) - sizeof(struct SecurityChecksum);
    frameConfig.FrameData = frameData;
    frameConfig.FrameLength = frameLength;
    frameConfig.NumFramesPerCycle = numFramesPerCycle;
    frameConfig.SequenceCounter = sequenceCounter;
    frameConfig.MetaDataOffset = metaDataOffset;

    err = PrepareFrameForTx(&frameConfig);
    if (err)
        LogMessage(LOG_LEVEL_ERROR, "RtcTx: Failed to prepare frame for Tx!\n");

    /* Send it */
    ret = send(socketFd, frameData, frameLength, 0);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtcTx: send() for %" PRIu64 " failed: %s\n", sequenceCounter, strerror(errno));
        return;
    }

    StatRtcFrameSent(sequenceCounter);
}

static void RtcGenAndSendXdpFrames(struct SecurityContext *securityContext, struct XdpSocket *xsk,
                                   const unsigned char *txFrameData, size_t numFramesPerCycle, uint64_t sequenceCounter,
                                   uint32_t *frameNumber)
{
    uint32_t metaDataOffset = sizeof(struct VLANEthernetHeader) + offsetof(struct ProfinetRtHeader, MetaData);
    struct XdpGenConfig xdp;

    xdp.Mode = appConfig.RtcSecurityMode;
    xdp.SecurityContext = securityContext;
    xdp.IvPrefix = (const unsigned char *)appConfig.RtcSecurityIvPrefix;
    xdp.PayloadPattern =
        txFrameData + 1 * RTC_TX_FRAME_LENGTH + sizeof(struct VLANEthernetHeader) + sizeof(struct ProfinetSecureHeader);
    xdp.PayloadPatternLength = appConfig.RtcFrameLength - sizeof(struct VLANEthernetHeader) -
                               sizeof(struct ProfinetSecureHeader) - sizeof(struct SecurityChecksum);
    xdp.FrameLength = appConfig.RtcFrameLength;
    xdp.NumFramesPerCycle = numFramesPerCycle;
    xdp.FrameNumber = frameNumber;
    xdp.SequenceCounterBegin = sequenceCounter;
    xdp.MetaDataOffset = metaDataOffset;
    xdp.StatFunction = StatRtcFrameSent;

    XdpGenAndSendFrames(xsk, &xdp);
}

static void *RtcTxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    unsigned char receivedFrames[RTC_TX_FRAME_LENGTH * appConfig.RtcNumFramesPerCycle];
    struct SecurityContext *securityContext = threadContext->TxSecurityContext;
    const uint64_t cycleTimeNS = appConfig.ApplicationBaseCycleTimeNS;
    const bool mirrorEnabled = appConfig.RtcRxMirrorEnabled;
    unsigned char source[ETH_ALEN];
    struct timespec wakeupTime;
    uint64_t sequenceCounter = 0;
    int ret, socketFd;

    socketFd = threadContext->SocketFd;

    ret = GetInterfaceMacAddress(appConfig.RtcInterface, source, ETH_ALEN);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtcTx: Failed to get Source MAC address!\n");
        return NULL;
    }

    RtcInitializeFrames(threadContext->TxFrameData, 2, source, appConfig.RtcDestination);

    PrepareOpenssl(securityContext);

    ret = GetThreadStartTime(appConfig.ApplicationTxBaseOffsetNS, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtcTx: Failed to calculate thread start time: %s!\n", strerror(errno));
        return NULL;
    }

    while (!threadContext->Stop)
    {
        size_t i;

        if (!threadContext->IsFirst)
        {
            /*
             * Wait until signalled. These RTC frames have to be sent after
             * the TSN Low frames.
             */
            pthread_mutex_lock(&threadContext->DataMutex);
            pthread_cond_wait(&threadContext->DataCondVar, &threadContext->DataMutex);
            pthread_mutex_unlock(&threadContext->DataMutex);
        }
        else
        {
            /* Wait until next period */
            IncrementPeriod(&wakeupTime, cycleTimeNS);

            do
            {
                ret = clock_nanosleep(appConfig.ApplicationClockId, TIMER_ABSTIME, &wakeupTime, NULL);
            } while (ret == EINTR);

            if (ret)
            {
                LogMessage(LOG_LEVEL_ERROR, "RtcTx: clock_nanosleep() failed: %s\n", strerror(ret));
                return NULL;
            }
        }

        /*
         * Send RtcFrames, two possibilites:
         *  a) Generate it, or
         *  b) Use received ones if mirror enabled
         */
        if (!mirrorEnabled)
        {
            for (i = 0; i < appConfig.RtcNumFramesPerCycle; ++i)
                RtcGenAndSendFrame(securityContext, threadContext->TxFrameData, appConfig.RtcFrameLength,
                                   appConfig.RtcNumFramesPerCycle, socketFd, sequenceCounter++);
        }
        else
        {
            size_t len;

            RingBufferFetch(threadContext->MirrorBuffer, receivedFrames, sizeof(receivedFrames), &len);

            /* Len should be a multiple of frame size */
            for (i = 0; i < len / appConfig.RtcFrameLength; ++i)
                RtcSendFrame(receivedFrames + i * appConfig.RtcFrameLength, appConfig.RtcFrameLength,
                             appConfig.RtcNumFramesPerCycle, socketFd);
        }

        /* Signal next Tx thread */
        if (threadContext->Next)
        {
            pthread_mutex_lock(&threadContext->Next->DataMutex);
            if (threadContext->Next->NumFramesAvailable)
                pthread_cond_signal(&threadContext->Next->DataCondVar);
            pthread_mutex_unlock(&threadContext->Next->DataMutex);
        }
    }

    return NULL;
}

/*
 * This Tx thread routine differs to the standard one in terms of the sending
 * interface. This one uses the AF_XDP user space interface.
 */
static void *RtcXdpTxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    struct SecurityContext *securityContext = threadContext->TxSecurityContext;
    const uint64_t cycleTimeNS = appConfig.ApplicationBaseCycleTimeNS;
    const bool mirrorEnabled = appConfig.RtcRxMirrorEnabled;
    uint32_t frameNumber = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    const size_t numFrames = appConfig.RtcNumFramesPerCycle;
    unsigned char source[ETH_ALEN];
    struct timespec wakeupTime;
    uint64_t sequenceCounter = 0;
    unsigned char *frameData;
    struct XdpSocket *xsk;
    int ret;

    xsk = threadContext->Xsk;

    ret = GetInterfaceMacAddress(appConfig.RtcInterface, source, ETH_ALEN);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtcTx: Failed to get Source MAC address!\n");
        return NULL;
    }

    /* First half of umem area is for Rx, the second half is for Tx. */
    frameData = xsk_umem__get_data(xsk->Umem.Buffer, XDP_FRAME_SIZE * XSK_RING_PROD__DEFAULT_NUM_DESCS);

    /* Initialize all Tx frames */
    RtcInitializeFrames(frameData, XSK_RING_CONS__DEFAULT_NUM_DESCS, source, appConfig.RtcDestination);
    RtcInitializeFrames(threadContext->TxFrameData, 2, source, appConfig.RtcDestination);

    PrepareOpenssl(securityContext);

    ret = GetThreadStartTime(appConfig.ApplicationTxBaseOffsetNS, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtcTx: Failed to calculate thread start time: %s!\n", strerror(errno));
        return NULL;
    }

    while (!threadContext->Stop)
    {
        if (!threadContext->IsFirst)
        {
            /*
             * Wait until signalled. These RTC frames have to be sent after
             * the TSN Low frames.
             */
            pthread_mutex_lock(&threadContext->DataMutex);
            pthread_cond_wait(&threadContext->DataCondVar, &threadContext->DataMutex);
            pthread_mutex_unlock(&threadContext->DataMutex);
        }
        else
        {
            /* Wait until next period */
            IncrementPeriod(&wakeupTime, cycleTimeNS);

            do
            {
                ret = clock_nanosleep(appConfig.ApplicationClockId, TIMER_ABSTIME, &wakeupTime, NULL);
            } while (ret == EINTR);

            if (ret)
            {
                LogMessage(LOG_LEVEL_ERROR, "RtcTx: clock_nanosleep() failed: %s\n", strerror(ret));
                return NULL;
            }
        }

        /*
         * Send RtcFrames, two possibilites:
         *  a) Generate it, or
         *  b) Use received ones if mirror enabled
         */
        if (!mirrorEnabled)
        {
            RtcGenAndSendXdpFrames(securityContext, xsk, threadContext->TxFrameData, numFrames, sequenceCounter,
                                   &frameNumber);
            sequenceCounter += numFrames;
        }
        else
        {
            unsigned int received;
            uint64_t i;

            pthread_mutex_lock(&threadContext->XdpDataMutex);

            received = threadContext->ReceivedFrames;

            sequenceCounter = threadContext->RxSequenceCounter - received;

            /*
             * The XDP receiver stored the frames within the umem
             * area and populated the Tx ring. Now, the Tx ring can
             * be committed to the kernel. Furthermore, already
             * transmitted frames from last cycle can be recycled
             * for Rx.
             */

            xsk_ring_prod__submit(&xsk->Tx, received);

            for (i = sequenceCounter; i < sequenceCounter + received; ++i)
                StatRtcFrameSent(i);

            xsk->OutstandingTx += received;
            threadContext->ReceivedFrames = 0;
            XdpCompleteTx(xsk);

            pthread_mutex_unlock(&threadContext->XdpDataMutex);
        }

        /* Signal next Tx thread */
        if (threadContext->Next)
        {
            pthread_mutex_lock(&threadContext->Next->DataMutex);
            if (threadContext->Next->NumFramesAvailable)
                pthread_cond_signal(&threadContext->Next->DataCondVar);
            pthread_mutex_unlock(&threadContext->Next->DataMutex);
        }
    }

    return NULL;
}

static int RtcRxFrame(void *data, unsigned char *frameData, size_t len)
{
    struct ThreadContext *threadContext = data;
    const unsigned char *expectedPattern = (const unsigned char *)appConfig.RtcPayloadPattern;
    struct SecurityContext *securityContext = threadContext->RxSecurityContext;
    const size_t expectedPatternLength = appConfig.RtcPayloadPatternLength;
    const size_t numFramesPerCycle = appConfig.RtcNumFramesPerCycle;
    const bool mirrorEnabled = appConfig.RtcRxMirrorEnabled;
    const bool ignoreRxErrors = appConfig.RtcIgnoreRxErrors;
    size_t expectedFrameLength = appConfig.RtcFrameLength;
    unsigned char newFrame[RTC_TX_FRAME_LENGTH];
    struct ProfinetSecureHeader *srt;
    struct ProfinetRtHeader *rt;
    uint64_t sequenceCounter;
    bool vlanTagMissing;
    void *p = frameData;
    struct ethhdr *eth;
    uint16_t frameId;
    uint16_t proto;

    if (len < sizeof(struct VLANEthernetHeader))
    {
        LogMessage(LOG_LEVEL_WARNING, "RtcRx: Too small frame received!\n");
        return -EINVAL;
    }

    eth = p;
    if (eth->h_proto == htons(ETH_P_8021Q))
    {
        struct VLANEthernetHeader *veth = p;

        proto = veth->VLANEncapsulatedProto;
        p += sizeof(*veth);
        vlanTagMissing = false;
    }
    else
    {
        proto = eth->h_proto;
        p += sizeof(*eth);
        expectedFrameLength -= sizeof(struct VLANHeader);
        vlanTagMissing = true;
    }

    if (proto != htons(ETH_P_PROFINET_RT))
    {
        LogMessage(LOG_LEVEL_WARNING, "RtcRx: Not a Profinet frame received!\n");
        return -EINVAL;
    }

    /*
     * Check frame length: VLAN tag might be stripped or not. Check it.
     */
    if (len != expectedFrameLength)
    {
        LogMessage(LOG_LEVEL_WARNING, "RtcRx: Frame with wrong length received!\n");
        return -EINVAL;
    }

    /*
     * Check cycle counter, frame id range and payload.
     */
    if (appConfig.RtcSecurityMode == SECURITY_MODE_NONE)
    {
        rt = p;
        p += sizeof(*rt);

        frameId = be16toh(rt->FrameId);
        sequenceCounter = MetaDataToSequenceCounter(&rt->MetaData, numFramesPerCycle);
    }
    else if (appConfig.RtcSecurityMode == SECURITY_MODE_AO)
    {
        unsigned char *beginOfSecurityChecksum;
        unsigned char *beginOfAadData;
        size_t sizeOfEthHeader;
        size_t sizeOfAadData;
        struct SecurityIv iv;
        int ret;

        srt = p;
        p += sizeof(*srt);

        frameId = be16toh(srt->FrameId);
        sequenceCounter = MetaDataToSequenceCounter(&srt->MetaData, numFramesPerCycle);

        /* Authenticate received Profinet Frame */
        sizeOfEthHeader = vlanTagMissing ? sizeof(struct ethhdr) : sizeof(struct VLANEthernetHeader);

        beginOfAadData = frameData + sizeOfEthHeader;
        sizeOfAadData = len - sizeOfEthHeader - sizeof(struct SecurityChecksum);
        beginOfSecurityChecksum = frameData + (len - sizeof(struct SecurityChecksum));

        PrepareIv((const unsigned char *)appConfig.RtcSecurityIvPrefix, sequenceCounter, &iv);

        ret = SecurityDecrypt(securityContext, NULL, 0, beginOfAadData, sizeOfAadData, beginOfSecurityChecksum,
                              (unsigned char *)&iv, NULL);
        if (ret)
            LogMessage(LOG_LEVEL_WARNING, "RtcRx: frame[%" PRIu64 "] Not authentificated\n", sequenceCounter);
    }
    else
    {
        unsigned char plaintext[RTC_TX_FRAME_LENGTH];
        unsigned char *beginOfSecurityChecksum;
        unsigned char *beginOfCiphertext;
        unsigned char *beginOfAadData;
        size_t sizeOfCiphertext;
        size_t sizeOfEthHeader;
        size_t sizeOfAadData;
        struct SecurityIv iv;
        int ret;

        srt = p;
        p += sizeof(*srt);

        frameId = be16toh(srt->FrameId);
        sequenceCounter = MetaDataToSequenceCounter(&srt->MetaData, numFramesPerCycle);

        /* Authenticate received Profinet Frame */
        sizeOfEthHeader = vlanTagMissing ? sizeof(struct ethhdr) : sizeof(struct VLANEthernetHeader);

        beginOfAadData = frameData + sizeOfEthHeader;
        sizeOfAadData = sizeof(*srt);
        beginOfSecurityChecksum = frameData + (len - sizeof(struct SecurityChecksum));
        beginOfCiphertext = frameData + sizeOfEthHeader + sizeof(*srt);
        sizeOfCiphertext = len - sizeof(struct VLANEthernetHeader) - sizeof(struct ProfinetSecureHeader) -
                           sizeof(struct SecurityChecksum);

        PrepareIv((const unsigned char *)appConfig.RtcSecurityIvPrefix, sequenceCounter, &iv);

        ret = SecurityDecrypt(securityContext, beginOfCiphertext, sizeOfCiphertext, beginOfAadData, sizeOfAadData,
                              beginOfSecurityChecksum, (unsigned char *)&iv, plaintext);
        if (ret)
            LogMessage(LOG_LEVEL_WARNING, "RtcRx: frame[%" PRIu64 "] Not authentificated and decrypted\n",
                       sequenceCounter);

        /* plaintext points to the decrypted payload */
        p = plaintext;
    }

    StatRtcFrameReceived(sequenceCounter);

    if (frameId != 0x8000)
        LogMessage(LOG_LEVEL_WARNING, "RtcRx: frame[%" PRIu64 "] FrameId mismatch: 0x%4x!\n", sequenceCounter, 0x8000);

    if (sequenceCounter != threadContext->RxSequenceCounter)
    {
        if (!ignoreRxErrors)
            LogMessage(LOG_LEVEL_WARNING, "RtcRx: frame[%" PRIu64 "] SequenceCounter mismatch: %" PRIu64 "!\n",
                       sequenceCounter, threadContext->RxSequenceCounter);
        threadContext->RxSequenceCounter++;
    }

    if (memcmp(p, expectedPattern, expectedPatternLength))
        LogMessage(LOG_LEVEL_WARNING, "RtcRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n", sequenceCounter);

    threadContext->RxSequenceCounter++;

    /*
     * If mirror enabled, assemble and store the frame for Tx later.
     *
     * In case of XDP the Rx umem area will be reused for Tx.
     */
    if (!mirrorEnabled)
        return 0;

    if (appConfig.RtcXdpEnabled)
    {
        /* Re-add vlan tag */
        if (vlanTagMissing)
            InsertVlanTag(frameData, len, appConfig.RtcVid | RTC_PCP_VALUE << VLAN_PCP_SHIFT);

        /* Swap mac addresses inline */
        SwapMacAddresses(frameData, len);
    }
    else
    {
        /*
         * Build new frame for Tx with VLAN info.
         */
        BuildVLANFrameFromRx(frameData, len, newFrame, sizeof(newFrame), ETH_P_PROFINET_RT,
                             appConfig.RtcVid | RTC_PCP_VALUE << VLAN_PCP_SHIFT);

        /*
         * Store the new frame.
         */
        RingBufferAdd(threadContext->MirrorBuffer, newFrame, len + sizeof(struct VLANHeader));
    }

    return 0;
}

static void *RtcRxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    unsigned char frame[RTC_TX_FRAME_LENGTH];
    int socketFd;

    socketFd = threadContext->SocketFd;

    PrepareOpenssl(threadContext->RxSecurityContext);

    while (!threadContext->Stop)
    {
        ssize_t len;

        /* Wait for RTC frame */
        len = recv(socketFd, frame, sizeof(frame), 0);
        if (len < 0)
        {
            LogMessage(LOG_LEVEL_ERROR, "RtcRx: recv() failed: %s\n", strerror(errno));
            return NULL;
        }
        if (len == 0)
            return NULL;

        RtcRxFrame(threadContext, frame, len);
    }

    return NULL;
}

static void *RtcXdpRxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    struct XdpSocket *xsk = threadContext->Xsk;
    const long long cycleTimeNS = appConfig.ApplicationBaseCycleTimeNS;
    const size_t frameLength = appConfig.RtcFrameLength;
    const bool mirrorEnabled = appConfig.RtcRxMirrorEnabled;
    struct timespec wakeupTime;
    int ret;

    PrepareOpenssl(threadContext->RxSecurityContext);

    ret = GetThreadStartTime(appConfig.ApplicationRxBaseOffsetNS, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtcRx: Failed to calculate thread start time: %s!\n", strerror(errno));
        return NULL;
    }

    while (!threadContext->Stop)
    {
        unsigned int received;

        /* Wait until next period */
        IncrementPeriod(&wakeupTime, cycleTimeNS);

        do
        {
            ret = clock_nanosleep(appConfig.ApplicationClockId, TIMER_ABSTIME, &wakeupTime, NULL);
        } while (ret == EINTR);

        if (ret)
        {
            LogMessage(LOG_LEVEL_ERROR, "RtcRx: clock_nanosleep() failed: %s\n", strerror(ret));
            return NULL;
        }

        pthread_mutex_lock(&threadContext->XdpDataMutex);
        received = XdpReceiveFrames(xsk, frameLength, mirrorEnabled, RtcRxFrame, threadContext);
        threadContext->ReceivedFrames = received;
        pthread_mutex_unlock(&threadContext->XdpDataMutex);
    }

    return NULL;
}

int RtcThreadsCreate(struct ThreadContext *threadContext)
{
    int ret;

    if (!CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Rtc))
        goto out;

    InitMutex(&threadContext->DataMutex);
    InitConditionVariable(&threadContext->DataCondVar);

    threadContext->TxFrameData = calloc(2, RTC_TX_FRAME_LENGTH);
    if (!threadContext->TxFrameData)
    {
        fprintf(stderr, "Failed to allocate RtcTxFrameData\n");
        ret = -ENOMEM;
        goto err_tx;
    }

    /*
     * For XDP a AF_XDP socket is allocated. Otherwise a Linux raw socket is
     * used.
     */
    if (appConfig.RtcXdpEnabled)
    {
        threadContext->SocketFd = 0;
        threadContext->Xsk = XdpOpenSocket(appConfig.RtcInterface, appConfig.ApplicationXdpProgram,
                                           appConfig.RtcRxQueue, appConfig.RtcXdpSkbMode, appConfig.RtcXdpZcMode,
                                           appConfig.RtcXdpWakeupMode, appConfig.RtcXdpBusyPollMode);
        if (!threadContext->Xsk)
        {
            fprintf(stderr, "Failed to create Rtc Xdp socket!\n");
            ret = -ENOMEM;
            goto err_socket;
        }
    }
    else
    {
        threadContext->Xsk = NULL;
        threadContext->SocketFd = CreateRTCSocket();
        if (threadContext->SocketFd < 0)
        {
            fprintf(stderr, "Failed to create RtcSocket!\n");
            ret = -errno;
            goto err_socket;
        }
    }

    /*
     * Same as above. For XDP the umem area is used.
     */
    if (appConfig.RtcRxMirrorEnabled && !appConfig.RtcXdpEnabled)
    {
        /*
         * Per period the expectation is: RtcNumFramesPerCycle * MAX_FRAME
         */
        threadContext->MirrorBuffer = RingBufferAllocate(RTC_TX_FRAME_LENGTH * appConfig.RtcNumFramesPerCycle);
        if (!threadContext->MirrorBuffer)
        {
            fprintf(stderr, "Failed to allocate Rtc Mirror RingBuffer!\n");
            ret = -ENOMEM;
            goto err_thread;
        }
    }

    if (appConfig.RtcSecurityMode != SECURITY_MODE_NONE)
    {
        threadContext->TxSecurityContext =
            SecurityInit(appConfig.RtcSecurityAlgorithm, (unsigned char *)appConfig.RtcSecurityKey);
        if (!threadContext->TxSecurityContext)
        {
            fprintf(stderr, "Failed to initialize Tx security context!\n");
            ret = -ENOMEM;
            goto err_tx_sec;
        }

        threadContext->RxSecurityContext =
            SecurityInit(appConfig.RtcSecurityAlgorithm, (unsigned char *)appConfig.RtcSecurityKey);
        if (!threadContext->RxSecurityContext)
        {
            fprintf(stderr, "Failed to initialize Rx security context!\n");
            ret = -ENOMEM;
            goto err_rx_sec;
        }
    }
    else
    {
        threadContext->TxSecurityContext = NULL;
        threadContext->RxSecurityContext = NULL;
    }

    if (appConfig.RtcTxEnabled)
    {
        ret = CreateRtThread(&threadContext->TxTaskId, "RtcTxThread", appConfig.RtcTxThreadPriority,
                             appConfig.RtcTxThreadCpu,
                             appConfig.RtcXdpEnabled ? RtcXdpTxThreadRoutine : RtcTxThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create Rtc Tx thread!\n");
            goto err_thread_create1;
        }
    }

    if (appConfig.RtcRxEnabled)
    {
        ret = CreateRtThread(&threadContext->RxTaskId, "RtcRxThread", appConfig.RtcRxThreadPriority,
                             appConfig.RtcRxThreadCpu,
                             appConfig.RtcXdpEnabled ? RtcXdpRxThreadRoutine : RtcRxThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create Rtc Rx thread!\n");
            goto err_thread_create2;
        }
    }

out:
    ret = 0;

    return ret;

err_thread_create2:
    if (appConfig.RtcTxEnabled)
    {
        threadContext->Stop = 1;
        pthread_join(threadContext->TxTaskId, NULL);
    }
err_thread_create1:
    SecurityExit(threadContext->RxSecurityContext);
err_rx_sec:
    SecurityExit(threadContext->TxSecurityContext);
err_tx_sec:
    RingBufferFree(threadContext->MirrorBuffer);
err_thread:
    if (threadContext->SocketFd)
        close(threadContext->SocketFd);
    if (threadContext->Xsk)
        XdpCloseSocket(threadContext->Xsk, appConfig.RtcInterface, appConfig.RtcXdpSkbMode);
err_socket:
    free(threadContext->TxFrameData);
err_tx:
    return ret;
}

void RtcThreadsFree(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    SecurityExit(threadContext->TxSecurityContext);
    SecurityExit(threadContext->RxSecurityContext);

    RingBufferFree(threadContext->MirrorBuffer);

    free(threadContext->TxFrameData);

    if (threadContext->SocketFd > 0)
        close(threadContext->SocketFd);

    if (threadContext->Xsk)
        XdpCloseSocket(threadContext->Xsk, appConfig.RtcInterface, appConfig.RtcXdpSkbMode);
}

void RtcThreadsStop(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    threadContext->Stop = 1;
    if (appConfig.RtcRxEnabled)
    {
        pthread_kill(threadContext->RxTaskId, SIGTERM);
        pthread_join(threadContext->RxTaskId, NULL);
    }
    if (appConfig.RtcTxEnabled)
        pthread_join(threadContext->TxTaskId, NULL);
}

void RtcThreadsWaitForFinish(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    if (appConfig.RtcRxEnabled)
        pthread_join(threadContext->RxTaskId, NULL);
    if (appConfig.RtcTxEnabled)
        pthread_join(threadContext->TxTaskId, NULL);
}
