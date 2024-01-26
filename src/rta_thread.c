// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <pthread.h>
#include <signal.h>
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
#include "net_def.h"
#include "rta_thread.h"
#include "security.h"
#include "stat.h"
#include "utils.h"

static void RtaInitializeFrames(unsigned char *frameData, size_t numFrames, const unsigned char *source,
                                const unsigned char *destination)
{
    size_t i;

    for (i = 0; i < numFrames; ++i)
        InitializeProfinetFrame(appConfig.RtaSecurityMode, frameData + i * RTA_TX_FRAME_LENGTH, RTA_TX_FRAME_LENGTH,
                                source, destination, appConfig.RtaPayloadPattern, appConfig.RtaPayloadPatternLength,
                                appConfig.RtaVid | RTA_PCP_VALUE << VLAN_PCP_SHIFT, 0xfc01);
}

static void RtaSendFrame(const unsigned char *frameData, size_t frameLength, size_t numFramesPerCycle, int socketFd)
{
    struct ProfinetSecureHeader *srt;
    struct VLANEthernetHeader *eth;
    struct ProfinetRtHeader *rt;
    uint64_t sequenceCounter;
    ssize_t ret;

    if (appConfig.RtaSecurityMode == SECURITY_MODE_NONE)
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
        LogMessage(LOG_LEVEL_ERROR, "RtaTx: send() for %" PRIu64 " failed: %s\n", sequenceCounter, strerror(errno));
        return;
    }

    StatFrameSent(RTA_FRAME_TYPE, sequenceCounter);
}

static void RtaGenAndSendFrame(struct SecurityContext *securityContext, unsigned char *frameData, size_t frameLength,
                               size_t numFramesPerCycle, int socketFd, uint64_t sequenceCounter)
{
    uint32_t metaDataOffset = sizeof(struct VLANEthernetHeader) + offsetof(struct ProfinetRtHeader, MetaData);
    struct PrepareFrameConfig frameConfig;
    ssize_t ret;
    int err;

    frameConfig.Mode = appConfig.RtaSecurityMode;
    frameConfig.SecurityContext = securityContext;
    frameConfig.IvPrefix = (const unsigned char *)appConfig.RtaSecurityIvPrefix;
    frameConfig.PayloadPattern =
        frameData + 1 * RTA_TX_FRAME_LENGTH + sizeof(struct VLANEthernetHeader) + sizeof(struct ProfinetSecureHeader);
    frameConfig.PayloadPatternLength = frameLength - sizeof(struct VLANEthernetHeader) -
                                       sizeof(struct ProfinetSecureHeader) - sizeof(struct SecurityChecksum);
    frameConfig.FrameData = frameData;
    frameConfig.FrameLength = frameLength;
    frameConfig.NumFramesPerCycle = numFramesPerCycle;
    frameConfig.SequenceCounter = sequenceCounter;
    frameConfig.MetaDataOffset = metaDataOffset;

    err = PrepareFrameForTx(&frameConfig);
    if (err)
        LogMessage(LOG_LEVEL_ERROR, "RtaTx: Failed to prepare frame for Tx!\n");

    /* Send it */
    ret = send(socketFd, frameData, frameLength, 0);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtaTx: send() for %" PRIu64 " failed: %s\n", sequenceCounter, strerror(errno));
        return;
    }

    StatFrameSent(RTA_FRAME_TYPE, sequenceCounter);
}

static void RtaGenAndSendXdpFrames(struct SecurityContext *securityContext, struct XdpSocket *xsk,
                                   const unsigned char *txFrameData, size_t numFramesPerCycle, uint64_t sequenceCounter,
                                   uint32_t *frameNumber)
{
    uint32_t metaDataOffset = sizeof(struct VLANEthernetHeader) + offsetof(struct ProfinetRtHeader, MetaData);
    struct XdpGenConfig xdp;

    xdp.Mode = appConfig.RtaSecurityMode;
    xdp.SecurityContext = securityContext;
    xdp.IvPrefix = (const unsigned char *)appConfig.RtaSecurityIvPrefix;
    xdp.PayloadPattern =
        txFrameData + 1 * RTA_TX_FRAME_LENGTH + sizeof(struct VLANEthernetHeader) + sizeof(struct ProfinetSecureHeader);
    xdp.PayloadPatternLength = appConfig.RtaFrameLength - sizeof(struct VLANEthernetHeader) -
                               sizeof(struct ProfinetSecureHeader) - sizeof(struct SecurityChecksum);
    xdp.FrameLength = appConfig.RtaFrameLength;
    xdp.NumFramesPerCycle = numFramesPerCycle;
    xdp.FrameNumber = frameNumber;
    xdp.SequenceCounterBegin = sequenceCounter;
    xdp.MetaDataOffset = metaDataOffset;
    xdp.FrameType = RTA_FRAME_TYPE;

    XdpGenAndSendFrames(xsk, &xdp);
}

static void *RtaTxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    unsigned char receivedFrames[RTA_TX_FRAME_LENGTH * appConfig.RtaNumFramesPerCycle];
    struct SecurityContext *securityContext = threadContext->TxSecurityContext;
    const bool mirrorEnabled = appConfig.RtaRxMirrorEnabled;
    unsigned char source[ETH_ALEN];
    uint64_t sequenceCounter = 0;
    int ret, socketFd;
    pthread_mutex_t *mutex = &threadContext->DataMutex;
    pthread_cond_t *cond = &threadContext->DataCondVar;

    socketFd = threadContext->SocketFd;

    ret = GetInterfaceMacAddress(appConfig.RtaInterface, source, ETH_ALEN);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtaTx: Failed to get Source MAC address!\n");
        return NULL;
    }

    RtaInitializeFrames(threadContext->TxFrameData, 2, source, appConfig.RtaDestination);

    PrepareOpenssl(securityContext);

    while (!threadContext->Stop)
    {
        size_t numFrames, i;

        /*
         * Wait until signalled. These RTA frames have to be sent after
         * the RTC frames. Therefore, the RTC TxThread signals this one
         * here.
         */
        pthread_mutex_lock(mutex);
        pthread_cond_wait(cond, mutex);
        numFrames = threadContext->NumFramesAvailable;
        threadContext->NumFramesAvailable = 0;
        pthread_mutex_unlock(mutex);

        /*
         * Send RtaFrames, two possibilites:
         *  a) Generate it, or
         *  b) Use received ones if mirror enabled
         */
        if (!mirrorEnabled)
        {
            /* Send RtaFrames */
            for (i = 0; i < numFrames; ++i)
                RtaGenAndSendFrame(securityContext, threadContext->TxFrameData, appConfig.RtaFrameLength,
                                   appConfig.RtaNumFramesPerCycle, socketFd, sequenceCounter++);
        }
        else
        {
            size_t len;

            RingBufferFetch(threadContext->MirrorBuffer, receivedFrames, sizeof(receivedFrames), &len);

            /* Len should be a multiple of frame size */
            for (i = 0; i < len / appConfig.RtaFrameLength; ++i)
                RtaSendFrame(receivedFrames + i * appConfig.RtaFrameLength, appConfig.RtaFrameLength,
                             appConfig.RtaNumFramesPerCycle, socketFd);

            pthread_mutex_lock(&threadContext->DataMutex);
            threadContext->NumFramesAvailable = 0;
            pthread_mutex_unlock(&threadContext->DataMutex);
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
static void *RtaXdpTxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    struct SecurityContext *securityContext = threadContext->TxSecurityContext;
    const bool mirrorEnabled = appConfig.RtaRxMirrorEnabled;
    uint32_t frameNumber = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    pthread_mutex_t *mutex = &threadContext->DataMutex;
    pthread_cond_t *cond = &threadContext->DataCondVar;
    unsigned char source[ETH_ALEN];
    uint64_t sequenceCounter = 0;
    unsigned char *frameData;
    struct XdpSocket *xsk;
    size_t numFrames;
    int ret;

    xsk = threadContext->Xsk;

    ret = GetInterfaceMacAddress(appConfig.RtaInterface, source, ETH_ALEN);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtaTx: Failed to get Source MAC address!\n");
        return NULL;
    }

    /* First half of umem area is for Rx, the second half is for Tx. */
    frameData = xsk_umem__get_data(xsk->Umem.Buffer, XDP_FRAME_SIZE * XSK_RING_PROD__DEFAULT_NUM_DESCS);

    /* Initialize all Tx frames */
    RtaInitializeFrames(frameData, XSK_RING_CONS__DEFAULT_NUM_DESCS, source, appConfig.RtaDestination);
    RtaInitializeFrames(threadContext->TxFrameData, 2, source, appConfig.RtaDestination);

    PrepareOpenssl(securityContext);

    while (!threadContext->Stop)
    {
        /*
         * Wait until signalled. These RTA frames have to be sent after
         * the RTC frames. Therefore, the RTC TxThread signals this one
         * here.
         */
        pthread_mutex_lock(mutex);
        pthread_cond_wait(cond, mutex);
        numFrames = threadContext->NumFramesAvailable;
        threadContext->NumFramesAvailable = 0;
        pthread_mutex_unlock(mutex);

        /*
         * Send RtaFrames, two possibilites:
         *  a) Generate it, or
         *  b) Use received ones if mirror enabled
         */
        if (!mirrorEnabled)
        {
            RtaGenAndSendXdpFrames(securityContext, xsk, threadContext->TxFrameData, numFrames, sequenceCounter,
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
                StatFrameSent(RTA_FRAME_TYPE, i);

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

static int RtaRxFrame(void *data, unsigned char *frameData, size_t len)
{
    struct ThreadContext *threadContext = data;
    const unsigned char *expectedPattern = (const unsigned char *)appConfig.RtaPayloadPattern;
    struct SecurityContext *securityContext = threadContext->RxSecurityContext;
    const size_t expectedPatternLength = appConfig.RtaPayloadPatternLength;
    const size_t numFramesPerCycle = appConfig.RtaNumFramesPerCycle;
    const bool mirrorEnabled = appConfig.RtaRxMirrorEnabled;
    const bool ignoreRxErrors = appConfig.RtaIgnoreRxErrors;
    size_t expectedFrameLength = appConfig.RtaFrameLength;
    bool outOfOrder, payloadMismatch, frameIdMismatch;
    unsigned char newFrame[RTA_TX_FRAME_LENGTH];
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
        LogMessage(LOG_LEVEL_WARNING, "RtaRx: Too small frame received!\n");
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
        LogMessage(LOG_LEVEL_WARNING, "RtaRx: Not a Profinet frame received!\n");
        return -EINVAL;
    }

    /*
     * Check frame length: VLAN tag might be stripped or not. Check it.
     */
    if (len != expectedFrameLength)
    {
        LogMessage(LOG_LEVEL_WARNING, "RtaRx: Frame with wrong length received!\n");
        return -EINVAL;
    }

    /*
     * Check cycle counter, frame id range and payload.
     */
    if (appConfig.RtaSecurityMode == SECURITY_MODE_NONE)
    {
        rt = p;
        p += sizeof(*rt);

        frameId = be16toh(rt->FrameId);
        sequenceCounter = MetaDataToSequenceCounter(&rt->MetaData, numFramesPerCycle);
    }
    else if (appConfig.RtaSecurityMode == SECURITY_MODE_AO)
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

        PrepareIv((const unsigned char *)appConfig.RtaSecurityIvPrefix, sequenceCounter, &iv);

        ret = SecurityDecrypt(securityContext, NULL, 0, beginOfAadData, sizeOfAadData, beginOfSecurityChecksum,
                              (unsigned char *)&iv, NULL);
        if (ret)
            LogMessage(LOG_LEVEL_WARNING, "RtaRx: frame[%" PRIu64 "] Not authentificated\n", sequenceCounter);
    }
    else
    {
        unsigned char plaintext[RTA_TX_FRAME_LENGTH];
        unsigned char *beginOfSecurityChecksum;
        unsigned char *beginOfCiphertext;
        unsigned char *beginOfAadData;
        size_t sizeOfCiphertext;
        size_t sizeOfEthHeader;
        size_t sizeOfAadData;
        struct SecurityIv iv;
        int ret;

        srt = p;

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

        PrepareIv((const unsigned char *)appConfig.RtaSecurityIvPrefix, sequenceCounter, &iv);

        ret = SecurityDecrypt(securityContext, beginOfCiphertext, sizeOfCiphertext, beginOfAadData, sizeOfAadData,
                              beginOfSecurityChecksum, (unsigned char *)&iv, plaintext);
        if (ret)
            LogMessage(LOG_LEVEL_WARNING, "RtaRx: frame[%" PRIu64 "] Not authentificated and decrypted\n",
                       sequenceCounter);

        /* plaintext points to the decrypted payload */
        p = plaintext;
    }

    outOfOrder = sequenceCounter != threadContext->RxSequenceCounter;
    payloadMismatch = memcmp(p, expectedPattern, expectedPatternLength);
    frameIdMismatch = frameId != 0xfc01;

    StatFrameReceived(RTA_FRAME_TYPE, sequenceCounter, outOfOrder, payloadMismatch, frameIdMismatch);

    if (frameIdMismatch)
        LogMessage(LOG_LEVEL_WARNING, "RtaRx: frame[%" PRIu64 "] FrameId mismatch: 0x%4x!\n", sequenceCounter, 0xfc01);

    if (outOfOrder)
    {
        if (!ignoreRxErrors)
            LogMessage(LOG_LEVEL_WARNING, "RtaRx: frame[%" PRIu64 "] SequenceCounter mismatch: %" PRIu64 "!\n",
                       sequenceCounter, threadContext->RxSequenceCounter);
        threadContext->RxSequenceCounter++;
    }

    if (payloadMismatch)
        LogMessage(LOG_LEVEL_WARNING, "RtaRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n", sequenceCounter);

    threadContext->RxSequenceCounter++;

    /*
     * If mirror enabled, assemble and store the frame for Tx later.
     *
     * In case of XDP the Rx umem area will be reused for Tx.
     */
    if (!mirrorEnabled)
        return 0;

    if (appConfig.RtaXdpEnabled)
    {
        /* Re-add vlan tag */
        if (vlanTagMissing)
            InsertVlanTag(frameData, len, appConfig.RtaVid | RTA_PCP_VALUE << VLAN_PCP_SHIFT);

        /* Swap mac addresses inline */
        SwapMacAddresses(frameData, len);
    }
    else
    {
        /*
         * Build new frame for Tx with VLAN info.
         */
        BuildVLANFrameFromRx(frameData, len, newFrame, sizeof(newFrame), ETH_P_PROFINET_RT,
                             appConfig.RtaVid | RTA_PCP_VALUE << VLAN_PCP_SHIFT);

        /*
         * Store the new frame.
         */
        RingBufferAdd(threadContext->MirrorBuffer, newFrame, len + sizeof(struct VLANHeader));
    }

    pthread_mutex_lock(&threadContext->DataMutex);
    threadContext->NumFramesAvailable++;
    pthread_mutex_unlock(&threadContext->DataMutex);

    return 0;
}

static void *RtaRxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    unsigned char frame[RTA_TX_FRAME_LENGTH];
    int socketFd;

    socketFd = threadContext->SocketFd;

    PrepareOpenssl(threadContext->RxSecurityContext);

    while (!threadContext->Stop)
    {
        ssize_t len;

        /* Wait for RTA frame */
        len = recv(socketFd, frame, sizeof(frame), 0);
        if (len < 0)
        {
            LogMessage(LOG_LEVEL_ERROR, "RtaRx: recv() failed: %s\n", strerror(errno));
            return NULL;
        }
        if (len == 0)
            return NULL;

        RtaRxFrame(threadContext, frame, len);
    }

    return NULL;
}

static void *RtaTxGenerationThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    pthread_mutex_t *mutex = &threadContext->DataMutex;
    uint64_t cycleTimeNS = appConfig.RtaBurstPeriodNS;
    uint64_t numFrames = appConfig.RtaNumFramesPerCycle;
    struct timespec wakeupTime;
    int ret;

    /*
     * The RTA frames are generated by bursts with a certain period. This
     * thread is responsible for generating it.
     */

    ret = GetThreadStartTime(0, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtaTxGen: Failed to calculate thread start time: %s!\n", strerror(errno));
        return NULL;
    }

    while (!threadContext->Stop)
    {
        /* Wait until next period */
        IncrementPeriod(&wakeupTime, cycleTimeNS);

        do
        {
            ret = clock_nanosleep(appConfig.ApplicationClockId, TIMER_ABSTIME, &wakeupTime, NULL);
        } while (ret == EINTR);

        if (ret)
        {
            LogMessage(LOG_LEVEL_ERROR, "RtaTxGen: clock_nanosleep() failed: %s\n", strerror(ret));
            return NULL;
        }

        /* Generate frames */
        pthread_mutex_lock(mutex);
        threadContext->NumFramesAvailable = numFrames;
        pthread_mutex_unlock(mutex);
    }

    return NULL;
}

static void *RtaXdpRxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    struct XdpSocket *xsk = threadContext->Xsk;
    const long long cycleTimeNS = appConfig.ApplicationBaseCycleTimeNS;
    const size_t frameLength = appConfig.RtaFrameLength;
    const bool mirrorEnabled = appConfig.RtaRxMirrorEnabled;
    struct timespec wakeupTime;
    int ret;

    PrepareOpenssl(threadContext->RxSecurityContext);

    ret = GetThreadStartTime(appConfig.ApplicationRxBaseOffsetNS, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "RtaRx: Failed to calculate thread start time: %s!\n", strerror(errno));
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
            LogMessage(LOG_LEVEL_ERROR, "RtaRx: clock_nanosleep() failed: %s\n", strerror(ret));
            return NULL;
        }

        pthread_mutex_lock(&threadContext->XdpDataMutex);
        received = XdpReceiveFrames(xsk, frameLength, mirrorEnabled, RtaRxFrame, threadContext);
        threadContext->ReceivedFrames = received;
        pthread_mutex_unlock(&threadContext->XdpDataMutex);
    }

    return NULL;
}

int RtaThreadsCreate(struct ThreadContext *threadContext)
{
    int ret;

    if (!CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Rta))
        goto out;

    InitMutex(&threadContext->DataMutex);
    InitMutex(&threadContext->XdpDataMutex);
    InitConditionVariable(&threadContext->DataCondVar);

    threadContext->TxFrameData = calloc(2, RTA_TX_FRAME_LENGTH);
    if (!threadContext->TxFrameData)
    {
        fprintf(stderr, "Failed to allocate RtaTxFrameData\n");
        ret = -ENOMEM;
        goto err_tx;
    }

    /*
     * For XDP a AF_XDP socket is allocated. Otherwise a Linux raw socket is
     * used.
     */
    if (appConfig.RtaXdpEnabled)
    {
        threadContext->SocketFd = 0;
        threadContext->Xsk = XdpOpenSocket(appConfig.RtaInterface, appConfig.ApplicationXdpProgram,
                                           appConfig.RtaRxQueue, appConfig.RtaXdpSkbMode, appConfig.RtaXdpZcMode,
                                           appConfig.RtaXdpWakeupMode, appConfig.RtaXdpBusyPollMode);
        if (!threadContext->Xsk)
        {
            fprintf(stderr, "Failed to create Rta Xdp socket!\n");
            ret = -ENOMEM;
            goto err_socket;
        }
    }
    else
    {
        threadContext->Xsk = NULL;
        threadContext->SocketFd = CreateRTASocket();
        if (threadContext->SocketFd < 0)
        {
            fprintf(stderr, "Failed to create RtaSocket!\n");
            ret = -errno;
            goto err_socket;
        }
    }

    /*
     * Same as above. For XDP the umem area is used.
     */
    if (appConfig.RtaRxMirrorEnabled && !appConfig.RtaXdpEnabled)
    {
        /*
         * Per period the expectation is: RtaNumFramesPerCycle * MAX_FRAME
         */
        threadContext->MirrorBuffer = RingBufferAllocate(RTA_TX_FRAME_LENGTH * appConfig.RtaNumFramesPerCycle);
        if (!threadContext->MirrorBuffer)
        {
            fprintf(stderr, "Failed to allocate Rta Mirror RingBuffer!\n");
            ret = -ENOMEM;
            goto err_buffer;
        }
    }

    if (appConfig.RtaSecurityMode != SECURITY_MODE_NONE)
    {
        threadContext->TxSecurityContext =
            SecurityInit(appConfig.RtaSecurityAlgorithm, (unsigned char *)appConfig.RtaSecurityKey);
        if (!threadContext->TxSecurityContext)
        {
            fprintf(stderr, "Failed to initialize Tx security context!\n");
            ret = -ENOMEM;
            goto err_tx_sec;
        }

        threadContext->RxSecurityContext =
            SecurityInit(appConfig.RtaSecurityAlgorithm, (unsigned char *)appConfig.RtaSecurityKey);
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

    if (appConfig.RtaTxEnabled)
    {
        ret = CreateRtThread(&threadContext->TxTaskId, "RtaTxThread", appConfig.RtaTxThreadPriority,
                             appConfig.RtaTxThreadCpu,
                             appConfig.RtaXdpEnabled ? RtaXdpTxThreadRoutine : RtaTxThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create Rta Tx Thread!\n");
            goto err_thread;
        }
    }

    if (appConfig.RtaTxGenEnabled)
    {
        ret = CreateRtThread(&threadContext->TxGenTaskId, "RtaTxGenThread", appConfig.RtaTxThreadPriority,
                             appConfig.RtaTxThreadCpu, RtaTxGenerationThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create Rta Tx Thread!\n");
            goto err_thread_txgen;
        }
    }

    if (appConfig.RtaRxEnabled)
    {
        ret = CreateRtThread(&threadContext->RxTaskId, "RtaRxThread", appConfig.RtaRxThreadPriority,
                             appConfig.RtaRxThreadCpu,
                             appConfig.RtaXdpEnabled ? RtaXdpRxThreadRoutine : RtaRxThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create Rta Rx Thread!\n");
            goto err_thread_rx;
        }
    }

out:
    ret = 0;

    return ret;

err_thread_rx:
    if (appConfig.RtaTxGenEnabled)
    {
        threadContext->Stop = 1;
        pthread_join(threadContext->TxGenTaskId, NULL);
    }
err_thread_txgen:
    if (appConfig.RtaTxEnabled)
    {
        threadContext->Stop = 1;
        pthread_join(threadContext->TxTaskId, NULL);
    }
err_thread:
    SecurityExit(threadContext->RxSecurityContext);
err_rx_sec:
    SecurityExit(threadContext->TxSecurityContext);
err_tx_sec:
    RingBufferFree(threadContext->MirrorBuffer);
err_buffer:
    if (threadContext->SocketFd)
        close(threadContext->SocketFd);
    if (threadContext->Xsk)
        XdpCloseSocket(threadContext->Xsk, appConfig.RtaInterface, appConfig.RtaXdpSkbMode);
err_socket:
    free(threadContext->TxFrameData);
err_tx:
    return ret;
}

void RtaThreadsFree(struct ThreadContext *threadContext)
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
        XdpCloseSocket(threadContext->Xsk, appConfig.RtaInterface, appConfig.RtaXdpSkbMode);
}

void RtaThreadsStop(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    threadContext->Stop = 1;
    if (appConfig.RtaRxEnabled)
    {
        pthread_kill(threadContext->RxTaskId, SIGTERM);
        pthread_join(threadContext->RxTaskId, NULL);
    }
    if (appConfig.RtaTxEnabled)
        pthread_join(threadContext->TxTaskId, NULL);
    if (appConfig.RtaTxGenEnabled)
        pthread_join(threadContext->TxGenTaskId, NULL);
}

void RtaThreadsWaitForFinish(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    if (appConfig.RtaRxEnabled)
        pthread_join(threadContext->RxTaskId, NULL);
    if (appConfig.RtaTxEnabled)
        pthread_join(threadContext->TxTaskId, NULL);
    if (appConfig.RtaTxGenEnabled)
        pthread_join(threadContext->TxGenTaskId, NULL);
}
