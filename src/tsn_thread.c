// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <endian.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>

#include "config.h"
#include "log.h"
#include "net.h"
#include "net_def.h"
#include "security.h"
#include "stat.h"
#include "tsn_thread.h"
#include "tx_time.h"
#include "utils.h"
#include "xdp.h"

static void TsnInitializeFrames(const struct TsnThreadConfiguration *tsnConfig, unsigned char *frameData,
                                size_t numFrames, const unsigned char *source, const unsigned char *destination)
{
    size_t i;

    for (i = 0; i < numFrames; ++i)
        InitializeProfinetFrame(tsnConfig->TsnSecurityMode, frameData + i * TSN_TX_FRAME_LENGTH, TSN_TX_FRAME_LENGTH,
                                source, destination, tsnConfig->TsnPayloadPattern, tsnConfig->TsnPayloadPatternLength,
                                tsnConfig->VlanId | tsnConfig->VlanPCP << VLAN_PCP_SHIFT, tsnConfig->FrameIdRangeStart);
}

static int TsnSendMessage(const struct TsnThreadConfiguration *tsnConfig, int socketFd, struct sockaddr_ll *destination,
                          unsigned char *frameData, size_t frameLength, uint64_t wakeupTime, uint64_t sequenceCounter,
                          uint64_t duration)
{
    int ret;

    if (tsnConfig->TsnTxTimeEnabled)
    {
        /* Send message but with specified transmission time. */
        char control[CMSG_SPACE(sizeof(uint64_t))] = {0};
        char trafficClass[128] = {0};
        struct cmsghdr *cmsg;
        struct msghdr msg;
        struct iovec iov;
        uint64_t txTime;

        snprintf(trafficClass, sizeof(trafficClass), "Tsn%s", tsnConfig->TsnSuffix);

        txTime = TxTimeGetFrameTxTime(wakeupTime, sequenceCounter, duration, tsnConfig->TsnNumFramesPerCycle,
                                      tsnConfig->TsnTxTimeOffsetNS, trafficClass);

        iov.iov_base = frameData;
        iov.iov_len = frameLength;

        memset(&msg, 0, sizeof(msg));
        msg.msg_name = destination;
        msg.msg_namelen = sizeof(*destination);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);

        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SO_TXTIME;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int64_t));
        *((uint64_t *)CMSG_DATA(cmsg)) = txTime;

        ret = sendmsg(socketFd, &msg, 0);
    }
    else
    {
        /* Regular send case. */
        ret = send(socketFd, frameData, frameLength, 0);
    }

    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "Tsn%sTx: send() for %" PRIu64 " failed: %s\n", tsnConfig->TsnSuffix,
                   sequenceCounter, strerror(errno));
        return -errno;
    }

    return 0;
}

static void TsnSendFrame(const struct TsnThreadConfiguration *tsnConfig, unsigned char *frameData, size_t frameLength,
                         int socketFd, struct sockaddr_ll *destination, uint64_t wakeupTime, uint64_t duration)
{
    struct ProfinetSecureHeader *srt;
    struct VLANEthernetHeader *eth;
    struct ProfinetRtHeader *rt;
    uint64_t sequenceCounter;
    ssize_t ret;

    if (tsnConfig->TsnSecurityMode == SECURITY_MODE_NONE)
    {
        /* Fetch meta data */
        rt = (struct ProfinetRtHeader *)(frameData + sizeof(*eth));
        sequenceCounter = MetaDataToSequenceCounter(&rt->MetaData, tsnConfig->TsnNumFramesPerCycle);
    }
    else
    {
        /* Fetch meta data */
        srt = (struct ProfinetSecureHeader *)(frameData + sizeof(*eth));
        sequenceCounter = MetaDataToSequenceCounter(&srt->MetaData, tsnConfig->TsnNumFramesPerCycle);
    }

    /* Send it */
    ret =
        TsnSendMessage(tsnConfig, socketFd, destination, frameData, frameLength, wakeupTime, sequenceCounter, duration);
    if (ret)
        return;

    StatFrameSent(tsnConfig->FrameType, sequenceCounter);
}

static void TsnGenAndSendFrame(const struct TsnThreadConfiguration *tsnConfig, struct SecurityContext *securityContext,
                               unsigned char *frameData, int socketFd, struct sockaddr_ll *destination,
                               uint64_t wakeupTime, uint64_t sequenceCounter, uint64_t duration)
{
    uint32_t metaDataOffset = sizeof(struct VLANEthernetHeader) + offsetof(struct ProfinetRtHeader, MetaData);
    struct PrepareFrameConfig frameConfig;
    ssize_t ret;
    int err;

    frameConfig.Mode = tsnConfig->TsnSecurityMode;
    frameConfig.SecurityContext = securityContext;
    frameConfig.IvPrefix = (const unsigned char *)tsnConfig->TsnSecurityIvPrefix;
    frameConfig.PayloadPattern =
        frameData + 1 * TSN_TX_FRAME_LENGTH + sizeof(struct VLANEthernetHeader) + sizeof(struct ProfinetSecureHeader);
    frameConfig.PayloadPatternLength = tsnConfig->TsnFrameLength - sizeof(struct VLANEthernetHeader) -
                                       sizeof(struct ProfinetSecureHeader) - sizeof(struct SecurityChecksum);
    frameConfig.FrameData = frameData;
    frameConfig.FrameLength = tsnConfig->TsnFrameLength;
    frameConfig.NumFramesPerCycle = tsnConfig->TsnNumFramesPerCycle;
    frameConfig.SequenceCounter = sequenceCounter;
    frameConfig.MetaDataOffset = metaDataOffset;

    err = PrepareFrameForTx(&frameConfig);
    if (err)
        LogMessage(LOG_LEVEL_ERROR, "Tsn%sTx: Failed to prepare frame for Tx!\n", tsnConfig->TsnSuffix);

    /* Send it */
    ret = TsnSendMessage(tsnConfig, socketFd, destination, frameData, tsnConfig->TsnFrameLength, wakeupTime,
                         sequenceCounter, duration);
    if (ret)
        return;

    StatFrameSent(tsnConfig->FrameType, sequenceCounter);
}

static void TsnGenAndSendXdpFrames(const struct TsnThreadConfiguration *tsnConfig,
                                   struct SecurityContext *securityContext, struct XdpSocket *xsk,
                                   const unsigned char *txFrameData, uint64_t sequenceCounter, uint32_t *frameNumber)
{
    uint32_t metaDataOffset = sizeof(struct VLANEthernetHeader) + offsetof(struct ProfinetRtHeader, MetaData);
    struct XdpGenConfig xdp;

    xdp.Mode = tsnConfig->TsnSecurityMode;
    xdp.SecurityContext = securityContext;
    xdp.IvPrefix = (const unsigned char *)tsnConfig->TsnSecurityIvPrefix;
    xdp.PayloadPattern =
        txFrameData + 1 * TSN_TX_FRAME_LENGTH + sizeof(struct VLANEthernetHeader) + sizeof(struct ProfinetSecureHeader);
    xdp.PayloadPatternLength = tsnConfig->TsnFrameLength - sizeof(struct VLANEthernetHeader) -
                               sizeof(struct ProfinetSecureHeader) - sizeof(struct SecurityChecksum);
    xdp.FrameLength = tsnConfig->TsnFrameLength;
    xdp.NumFramesPerCycle = tsnConfig->TsnNumFramesPerCycle;
    xdp.FrameNumber = frameNumber;
    xdp.SequenceCounterBegin = sequenceCounter;
    xdp.MetaDataOffset = metaDataOffset;
    xdp.FrameType = tsnConfig->FrameType;

    XdpGenAndSendFrames(xsk, &xdp);
}

static void *TsnTxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    const struct TsnThreadConfiguration *tsnConfig = threadContext->PrivateData;
    unsigned char receivedFrames[TSN_TX_FRAME_LENGTH * tsnConfig->TsnNumFramesPerCycle];
    struct SecurityContext *securityContext = threadContext->TxSecurityContext;
    const long long cycleTimeNS = appConfig.ApplicationBaseCycleTimeNS;
    const bool mirrorEnabled = tsnConfig->TsnRxMirrorEnabled;
    struct sockaddr_ll destination;
    unsigned char source[ETH_ALEN];
    struct timespec wakeupTime;
    uint64_t sequenceCounter = 0;
    unsigned int ifIndex;
    uint32_t linkSpeed;
    int ret, socketFd;
    uint64_t duration;

    socketFd = threadContext->SocketFd;

    ret = GetInterfaceMacAddress(tsnConfig->TsnInterface, source, ETH_ALEN);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "Tsn%sTx: Failed to get Source MAC address!\n", tsnConfig->TsnSuffix);
        return NULL;
    }

    ret = GetInterfaceLinkSpeed(tsnConfig->TsnInterface, &linkSpeed);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "Tsn%sTx: Failed to get link speed!\n", tsnConfig->TsnSuffix);
        return NULL;
    }

    ifIndex = if_nametoindex(tsnConfig->TsnInterface);
    if (!ifIndex)
    {
        LogMessage(LOG_LEVEL_ERROR, "Tsn%sTx: if_nametoindex() failed!\n", tsnConfig->TsnSuffix);
        return NULL;
    }

    memset(&destination, '\0', sizeof(destination));
    destination.sll_family = PF_PACKET;
    destination.sll_ifindex = ifIndex;
    destination.sll_halen = ETH_ALEN;
    memcpy(destination.sll_addr, tsnConfig->TsnDestination, ETH_ALEN);

    duration = TxTimeGetFrameDuration(linkSpeed, tsnConfig->TsnFrameLength);

    TsnInitializeFrames(tsnConfig, threadContext->TxFrameData, 2, source, tsnConfig->TsnDestination);

    PrepareOpenssl(securityContext);

    ret = GetThreadStartTime(appConfig.ApplicationTxBaseOffsetNS, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "Tsn%sTx: Failed to calculate thread start time: %s!\n", tsnConfig->TsnSuffix,
                   strerror(errno));
        return NULL;
    }

    while (!threadContext->Stop)
    {
        size_t i;

        if (!threadContext->IsFirst)
        {
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
                LogMessage(LOG_LEVEL_ERROR, "Tsn%sTx: clock_nanosleep() failed: %s\n", tsnConfig->TsnSuffix,
                           strerror(ret));
                return NULL;
            }
        }

        /*
         * Send TsnFrames, two possibilites:
         *  a) Generate it, or
         *  b) Use received ones if mirror enabled
         */
        if (!mirrorEnabled)
        {
            for (i = 0; i < tsnConfig->TsnNumFramesPerCycle; ++i)
                TsnGenAndSendFrame(tsnConfig, securityContext, threadContext->TxFrameData, socketFd, &destination,
                                   TsToNs(&wakeupTime), sequenceCounter++, duration);
        }
        else
        {
            size_t len;

            RingBufferFetch(threadContext->MirrorBuffer, receivedFrames, sizeof(receivedFrames), &len);

            /* Len should be a multiple of frame size */
            for (i = 0; i < len / tsnConfig->TsnFrameLength; ++i)
                TsnSendFrame(tsnConfig, receivedFrames + i * tsnConfig->TsnFrameLength, tsnConfig->TsnFrameLength,
                             socketFd, &destination, TsToNs(&wakeupTime), duration);
        }

        /* Signal next Tx thread */
        if (threadContext->Next)
        {
            pthread_mutex_lock(&threadContext->Next->DataMutex);
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
static void *TsnXdpTxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    const struct TsnThreadConfiguration *tsnConfig = threadContext->PrivateData;
    struct SecurityContext *securityContext = threadContext->TxSecurityContext;
    const long long cycleTimeNS = appConfig.ApplicationBaseCycleTimeNS;
    const bool mirrorEnabled = tsnConfig->TsnRxMirrorEnabled;
    uint32_t frameNumber = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    size_t numFrames = tsnConfig->TsnNumFramesPerCycle;
    unsigned char source[ETH_ALEN];
    struct timespec wakeupTime;
    uint64_t sequenceCounter = 0;
    unsigned char *frameData;
    struct XdpSocket *xsk;
    int ret;

    xsk = threadContext->Xsk;

    ret = GetInterfaceMacAddress(tsnConfig->TsnInterface, source, ETH_ALEN);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "Tsn%sTx: Failed to get Source MAC address!\n", tsnConfig->TsnSuffix);
        return NULL;
    }

    /* First half of umem area is for Rx, the second half is for Tx. */
    frameData = xsk_umem__get_data(xsk->Umem.Buffer, XDP_FRAME_SIZE * XSK_RING_PROD__DEFAULT_NUM_DESCS);

    /* Initialize all Tx frames */
    TsnInitializeFrames(tsnConfig, frameData, XSK_RING_CONS__DEFAULT_NUM_DESCS, source, tsnConfig->TsnDestination);
    TsnInitializeFrames(tsnConfig, threadContext->TxFrameData, 2, source, tsnConfig->TsnDestination);

    PrepareOpenssl(securityContext);

    ret = GetThreadStartTime(appConfig.ApplicationTxBaseOffsetNS, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "Tsn%sTx: Failed to calculate thread start time: %s!\n", tsnConfig->TsnSuffix,
                   strerror(errno));
        return NULL;
    }

    while (!threadContext->Stop)
    {
        if (!threadContext->IsFirst)
        {
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
                LogMessage(LOG_LEVEL_ERROR, "Tsn%sTx: clock_nanosleep() failed: %s\n", tsnConfig->TsnSuffix,
                           strerror(ret));
                return NULL;
            }
        }

        /*
         * Send TsnFrames, two possibilites:
         *  a) Generate it, or
         *  b) Use received ones if mirror enabled
         */
        if (!mirrorEnabled)
        {
            TsnGenAndSendXdpFrames(tsnConfig, securityContext, xsk, threadContext->TxFrameData, sequenceCounter,
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
                StatFrameSent(tsnConfig->FrameType, i);

            xsk->OutstandingTx += received;
            threadContext->ReceivedFrames = 0;
            XdpCompleteTx(xsk);

            pthread_mutex_unlock(&threadContext->XdpDataMutex);
        }

        /* Signal next Tx thread */
        if (threadContext->Next)
        {
            pthread_mutex_lock(&threadContext->Next->DataMutex);
            pthread_cond_signal(&threadContext->Next->DataCondVar);
            pthread_mutex_unlock(&threadContext->Next->DataMutex);
        }
    }

    return NULL;
}

static int TsnRxFrame(void *data, unsigned char *frameData, size_t len)
{
    struct ThreadContext *threadContext = data;
    const struct TsnThreadConfiguration *tsnConfig = threadContext->PrivateData;
    const unsigned char *expectedPattern = (const unsigned char *)tsnConfig->TsnPayloadPattern;
    struct SecurityContext *securityContext = threadContext->RxSecurityContext;
    const size_t expectedPatternLength = tsnConfig->TsnPayloadPatternLength;
    const bool mirrorEnabled = tsnConfig->TsnRxMirrorEnabled;
    const bool ignoreRxErrors = tsnConfig->TsnIgnoreRxErrors;
    size_t expectedFrameLength = tsnConfig->TsnFrameLength;
    bool outOfOrder, payloadMismatch, frameIdMismatch;
    unsigned char plaintext[TSN_TX_FRAME_LENGTH];
    unsigned char newFrame[TSN_TX_FRAME_LENGTH];
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
        LogMessage(LOG_LEVEL_WARNING, "Tsn%sRx: Too small frame received!\n", tsnConfig->TsnSuffix);
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
        LogMessage(LOG_LEVEL_WARNING, "Tsn%sRx: Not a Profinet frame received!\n", tsnConfig->TsnSuffix);
        return -EINVAL;
    }

    /*
     * Check frame length: VLAN tag might be stripped or not. Check it.
     */
    if (len != expectedFrameLength)
    {
        LogMessage(LOG_LEVEL_WARNING, "Tsn%sRx: Frame with wrong length received!\n", tsnConfig->TsnSuffix);
        return -EINVAL;
    }

    /*
     * Check cycle counter, frame id range and payload.
     */
    if (tsnConfig->TsnSecurityMode == SECURITY_MODE_NONE)
    {
        rt = p;
        p += sizeof(*rt);

        frameId = be16toh(rt->FrameId);
        sequenceCounter = MetaDataToSequenceCounter(&rt->MetaData, tsnConfig->TsnNumFramesPerCycle);
    }
    else if (tsnConfig->TsnSecurityMode == SECURITY_MODE_AO)
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
        sequenceCounter = MetaDataToSequenceCounter(&srt->MetaData, tsnConfig->TsnNumFramesPerCycle);

        /* Authenticate received Profinet Frame */
        sizeOfEthHeader = vlanTagMissing ? sizeof(struct ethhdr) : sizeof(struct VLANEthernetHeader);

        beginOfAadData = frameData + sizeOfEthHeader;
        sizeOfAadData = len - sizeOfEthHeader - sizeof(struct SecurityChecksum);
        beginOfSecurityChecksum = frameData + (len - sizeof(struct SecurityChecksum));

        PrepareIv((const unsigned char *)tsnConfig->TsnSecurityIvPrefix, sequenceCounter, &iv);

        ret = SecurityDecrypt(securityContext, NULL, 0, beginOfAadData, sizeOfAadData, beginOfSecurityChecksum,
                              (unsigned char *)&iv, NULL);
        if (ret)
            LogMessage(LOG_LEVEL_WARNING, "Tsn%sRx: frame[%" PRIu64 "] Not authentificated\n", tsnConfig->TsnSuffix,
                       sequenceCounter);
    }
    else
    {
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
        sequenceCounter = MetaDataToSequenceCounter(&srt->MetaData, tsnConfig->TsnNumFramesPerCycle);

        /* Authenticate received Profinet Frame */
        sizeOfEthHeader = vlanTagMissing ? sizeof(struct ethhdr) : sizeof(struct VLANEthernetHeader);

        beginOfAadData = frameData + sizeOfEthHeader;
        sizeOfAadData = sizeof(*srt);
        beginOfSecurityChecksum = frameData + (len - sizeof(struct SecurityChecksum));
        beginOfCiphertext = frameData + sizeOfEthHeader + sizeof(*srt);
        sizeOfCiphertext = len - sizeof(struct VLANEthernetHeader) - sizeof(struct ProfinetSecureHeader) -
                           sizeof(struct SecurityChecksum);

        PrepareIv((const unsigned char *)tsnConfig->TsnSecurityIvPrefix, sequenceCounter, &iv);

        ret = SecurityDecrypt(securityContext, beginOfCiphertext, sizeOfCiphertext, beginOfAadData, sizeOfAadData,
                              beginOfSecurityChecksum, (unsigned char *)&iv, plaintext);
        if (ret)
            LogMessage(LOG_LEVEL_WARNING, "Tsn%sRx: frame[%" PRIu64 "] Not authentificated and decrypted\n",
                       tsnConfig->TsnSuffix, sequenceCounter);

        /* plaintext points to the decrypted payload */
        p = plaintext;
    }

    outOfOrder = sequenceCounter != threadContext->RxSequenceCounter;
    payloadMismatch = memcmp(p, expectedPattern, expectedPatternLength);
    frameIdMismatch = frameId != tsnConfig->FrameIdRangeStart;

    StatFrameReceived(tsnConfig->FrameType, sequenceCounter, outOfOrder, payloadMismatch, frameIdMismatch);

    if (frameIdMismatch)
        LogMessage(LOG_LEVEL_WARNING, "Tsn%sRx: frame[%" PRIu64 "] FrameId mismatch: 0x%4x!\n", tsnConfig->TsnSuffix,
                   sequenceCounter, tsnConfig->FrameIdRangeStart);

    if (outOfOrder)
    {
        if (!ignoreRxErrors)
            LogMessage(LOG_LEVEL_WARNING, "Tsn%sRx: frame[%" PRIu64 "] SequenceCounter mismatch: %" PRIu64 "!\n",
                       tsnConfig->TsnSuffix, sequenceCounter, threadContext->RxSequenceCounter);
        threadContext->RxSequenceCounter++;
    }

    if (payloadMismatch)
        LogMessage(LOG_LEVEL_WARNING, "Tsn%sRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n", tsnConfig->TsnSuffix,
                   sequenceCounter);

    threadContext->RxSequenceCounter++;

    /*
     * If mirror enabled, assemble and store the frame for Tx later.
     *
     * In case of XDP the Rx umem area will be reused for Tx.
     */
    if (!mirrorEnabled)
        return 0;

    if (tsnConfig->TsnXdpEnabled)
    {
        /* Re-add vlan tag */
        if (vlanTagMissing)
            InsertVlanTag(frameData, len, tsnConfig->VlanId | tsnConfig->VlanPCP << VLAN_PCP_SHIFT);

        /* Swap mac addresses inline */
        SwapMacAddresses(frameData, len);
    }
    else
    {
        /*
         * Build new frame for Tx with VLAN info.
         */
        BuildVLANFrameFromRx(frameData, len, newFrame, sizeof(newFrame), ETH_P_PROFINET_RT,
                             tsnConfig->VlanId | tsnConfig->VlanPCP << VLAN_PCP_SHIFT);

        /*
         * Store the new frame.
         */
        RingBufferAdd(threadContext->MirrorBuffer, newFrame, len + sizeof(struct VLANHeader));
    }

    return 0;
}

static void *TsnRxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    const struct TsnThreadConfiguration *tsnConfig = threadContext->PrivateData;
    unsigned char frame[TSN_TX_FRAME_LENGTH];
    int socketFd;

    socketFd = threadContext->SocketFd;

    PrepareOpenssl(threadContext->RxSecurityContext);

    while (!threadContext->Stop)
    {
        ssize_t len;

        /* Wait for TSN frame */
        len = recv(socketFd, frame, sizeof(frame), 0);
        if (len < 0)
        {
            LogMessage(LOG_LEVEL_ERROR, "Tsn%sRx: recv() failed: %s\n", tsnConfig->TsnSuffix, strerror(errno));
            return NULL;
        }
        if (len == 0)
            return NULL;

        TsnRxFrame(threadContext, frame, len);
    }

    return NULL;
}

static void *TsnXdpRxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    const struct TsnThreadConfiguration *tsnConfig = threadContext->PrivateData;
    struct XdpSocket *xsk = threadContext->Xsk;
    const long long cycleTimeNS = appConfig.ApplicationBaseCycleTimeNS;
    const size_t frameLength = tsnConfig->TsnFrameLength;
    const bool mirrorEnabled = tsnConfig->TsnRxMirrorEnabled;
    struct timespec wakeupTime;
    int ret;

    PrepareOpenssl(threadContext->RxSecurityContext);

    ret = GetThreadStartTime(appConfig.ApplicationRxBaseOffsetNS, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "Tsn%sRx: Failed to calculate thread start time: %s!\n", tsnConfig->TsnSuffix,
                   strerror(errno));
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
            LogMessage(LOG_LEVEL_ERROR, "Tsn%sRx: clock_nanosleep() failed: %s\n", tsnConfig->TsnSuffix, strerror(ret));
            return NULL;
        }

        pthread_mutex_lock(&threadContext->XdpDataMutex);
        received = XdpReceiveFrames(xsk, frameLength, mirrorEnabled, TsnRxFrame, threadContext);
        threadContext->ReceivedFrames = received;
        pthread_mutex_unlock(&threadContext->XdpDataMutex);
    }

    return NULL;
}

int TsnThreadsCreate(struct ThreadContext *threadContext, struct TsnThreadConfiguration *tsnConfig)
{
    int ret;

    if (!strcmp(tsnConfig->TsnSuffix, "High") && !CONFIG_IS_TRAFFIC_CLASS_ACTIVE(TsnHigh))
    {
        ret = 0;
        goto out;
    }
    if (!strcmp(tsnConfig->TsnSuffix, "Low") && !CONFIG_IS_TRAFFIC_CLASS_ACTIVE(TsnLow))
    {
        ret = 0;
        goto out;
    }

    threadContext->PrivateData = tsnConfig;

    threadContext->TxFrameData = calloc(2, TSN_TX_FRAME_LENGTH);
    if (!threadContext->TxFrameData)
    {
        fprintf(stderr, "Failed to allocate TsnTxFrameData\n");
        ret = -ENOMEM;
        goto err_tx;
    }

    /*
     * For XDP a AF_XDP socket is allocated. Otherwise a Linux raw socket is
     * used.
     */
    if (tsnConfig->TsnXdpEnabled)
    {
        threadContext->SocketFd = 0;
        threadContext->Xsk = XdpOpenSocket(tsnConfig->TsnInterface, appConfig.ApplicationXdpProgram,
                                           tsnConfig->TsnRxQueue, tsnConfig->TsnXdpSkbMode, tsnConfig->TsnXdpZcMode,
                                           tsnConfig->TsnXdpWakeupMode, tsnConfig->TsnXdpBusyPollMode);
        if (!threadContext->Xsk)
        {
            fprintf(stderr, "Failed to create Tsn Xdp socket!\n");
            ret = -ENOMEM;
            goto err_socket;
        }
    }
    else
    {
        threadContext->Xsk = NULL;
        threadContext->SocketFd = tsnConfig->CreateTSNSocket();
        if (threadContext->SocketFd < 0)
        {
            fprintf(stderr, "Failed to create TSN Socket!\n");
            ret = -errno;
            goto err_socket;
        }
    }

    InitMutex(&threadContext->DataMutex);
    InitMutex(&threadContext->XdpDataMutex);
    InitConditionVariable(&threadContext->DataCondVar);

    /*
     * Same as above. For XDP the umem area is used.
     */
    if (tsnConfig->TsnRxMirrorEnabled && !tsnConfig->TsnXdpEnabled)
    {
        /*
         * Per period the expectation is: TsnNumFramesPerCycle * MAX_FRAME
         */
        threadContext->MirrorBuffer = RingBufferAllocate(TSN_TX_FRAME_LENGTH * tsnConfig->TsnNumFramesPerCycle);
        if (!threadContext->MirrorBuffer)
        {
            fprintf(stderr, "Failed to allocate Tsn Mirror RingBuffer!\n");
            ret = -ENOMEM;
            goto err_buffer;
        }
    }

    if (tsnConfig->TsnSecurityMode != SECURITY_MODE_NONE)
    {
        threadContext->TxSecurityContext =
            SecurityInit(tsnConfig->TsnSecurityAlgorithm, (unsigned char *)tsnConfig->TsnSecurityKey);
        if (!threadContext->TxSecurityContext)
        {
            fprintf(stderr, "Failed to initialize Tx security context!\n");
            ret = -ENOMEM;
            goto err_tx_sec;
        }

        threadContext->RxSecurityContext =
            SecurityInit(tsnConfig->TsnSecurityAlgorithm, (unsigned char *)tsnConfig->TsnSecurityKey);
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

    if (tsnConfig->TsnTxEnabled)
    {
        char threadName[128];

        snprintf(threadName, sizeof(threadName), "Tsn%sTxThread", tsnConfig->TsnSuffix);

        ret = CreateRtThread(&threadContext->TxTaskId, threadName, tsnConfig->TsnTxThreadPriority,
                             tsnConfig->TsnTxThreadCpu,
                             tsnConfig->TsnXdpEnabled ? TsnXdpTxThreadRoutine : TsnTxThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create Tsn Tx Thread!\n");
            goto err_thread;
        }
    }

    if (tsnConfig->TsnRxEnabled)
    {
        char threadName[128];

        snprintf(threadName, sizeof(threadName), "Tsn%sRxThread", tsnConfig->TsnSuffix);

        ret = CreateRtThread(&threadContext->RxTaskId, threadName, tsnConfig->TsnRxThreadPriority,
                             tsnConfig->TsnRxThreadCpu,
                             tsnConfig->TsnXdpEnabled ? TsnXdpRxThreadRoutine : TsnRxThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create Tsn Rx Thread!\n");
            goto err_thread_rx;
        }
    }

    ret = 0;

    return ret;

err_thread_rx:
    if (threadContext->TxTaskId)
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
        XdpCloseSocket(threadContext->Xsk, tsnConfig->TsnInterface, tsnConfig->TsnXdpSkbMode);
err_socket:
    free(threadContext->TxFrameData);
err_tx:
out:
    free(tsnConfig);
    return ret;
}

static void TsnThreadsFree(struct ThreadContext *threadContext)
{
    const struct TsnThreadConfiguration *tsnConfig;

    if (!threadContext)
        return;

    tsnConfig = threadContext->PrivateData;

    SecurityExit(threadContext->TxSecurityContext);
    SecurityExit(threadContext->RxSecurityContext);

    RingBufferFree(threadContext->MirrorBuffer);

    free(threadContext->TxFrameData);

    if (threadContext->SocketFd > 0)
        close(threadContext->SocketFd);

    if (threadContext->Xsk)
        XdpCloseSocket(threadContext->Xsk, tsnConfig->TsnInterface, tsnConfig->TsnXdpSkbMode);

    free((void *)tsnConfig);
}

static void TsnThreadsStop(struct ThreadContext *threadContext, int tsnLowRxEnabled, int tsnLowTxEnabled)
{
    if (!threadContext)
        return;

    threadContext->Stop = 1;
    if (tsnLowRxEnabled)
    {
        pthread_kill(threadContext->RxTaskId, SIGTERM);
        pthread_join(threadContext->RxTaskId, NULL);
    }
    if (tsnLowTxEnabled)
        pthread_join(threadContext->TxTaskId, NULL);
}

static void TsnThreadsWaitForFinish(struct ThreadContext *threadContext, int tsnLowRxEnabled, int tsnLowTxEnabled)
{
    if (!threadContext)
        return;

    if (tsnLowRxEnabled)
        pthread_join(threadContext->RxTaskId, NULL);
    if (tsnLowTxEnabled)
        pthread_join(threadContext->TxTaskId, NULL);
}

int TsnLowThreadsCreate(struct ThreadContext *tsnThreadContext)
{
    struct TsnThreadConfiguration *tsnConfig;

    tsnConfig = malloc(sizeof(*tsnConfig));
    if (!tsnConfig)
        return -ENOMEM;

    memset(tsnConfig, '\0', sizeof(*tsnConfig));
    tsnConfig->FrameType = TSN_LOW_FRAME_TYPE;
    tsnConfig->TsnSuffix = "Low";
    tsnConfig->TsnTxEnabled = appConfig.TsnLowTxEnabled;
    tsnConfig->TsnRxEnabled = appConfig.TsnLowRxEnabled;
    tsnConfig->TsnRxMirrorEnabled = appConfig.TsnLowRxMirrorEnabled;
    tsnConfig->TsnXdpEnabled = appConfig.TsnLowXdpEnabled;
    tsnConfig->TsnXdpSkbMode = appConfig.TsnLowXdpSkbMode;
    tsnConfig->TsnXdpZcMode = appConfig.TsnLowXdpZcMode;
    tsnConfig->TsnXdpWakeupMode = appConfig.TsnLowXdpWakeupMode;
    tsnConfig->TsnXdpBusyPollMode = appConfig.TsnLowXdpBusyPollMode;
    tsnConfig->TsnTxTimeEnabled = appConfig.TsnLowTxTimeEnabled;
    tsnConfig->TsnIgnoreRxErrors = appConfig.TsnLowIgnoreRxErrors;
    tsnConfig->TsnTxTimeOffsetNS = appConfig.TsnLowTxTimeOffsetNS;
    tsnConfig->TsnNumFramesPerCycle = appConfig.TsnLowNumFramesPerCycle;
    tsnConfig->TsnPayloadPattern = appConfig.TsnLowPayloadPattern;
    tsnConfig->TsnPayloadPatternLength = appConfig.TsnLowPayloadPatternLength;
    tsnConfig->TsnFrameLength = appConfig.TsnLowFrameLength;
    tsnConfig->TsnSecurityMode = appConfig.TsnLowSecurityMode;
    tsnConfig->TsnSecurityAlgorithm = appConfig.TsnLowSecurityAlgorithm;
    tsnConfig->TsnSecurityKey = appConfig.TsnLowSecurityKey;
    tsnConfig->TsnSecurityKeyLength = appConfig.TsnLowSecurityKeyLength;
    tsnConfig->TsnSecurityIvPrefix = appConfig.TsnLowSecurityIvPrefix;
    tsnConfig->TsnSecurityIvPrefixLength = appConfig.TsnLowSecurityIvPrefixLength;
    tsnConfig->TsnRxQueue = appConfig.TsnLowRxQueue;
    tsnConfig->TsnTxQueue = appConfig.TsnLowTxQueue;
    tsnConfig->TsnSocketPriority = appConfig.TsnLowSocketPriority;
    tsnConfig->TsnTxThreadPriority = appConfig.TsnLowTxThreadPriority;
    tsnConfig->TsnRxThreadPriority = appConfig.TsnLowRxThreadPriority;
    tsnConfig->TsnTxThreadCpu = appConfig.TsnLowTxThreadCpu;
    tsnConfig->TsnRxThreadCpu = appConfig.TsnLowRxThreadCpu;
    tsnConfig->TsnInterface = appConfig.TsnLowInterface;
    tsnConfig->TsnDestination = appConfig.TsnLowDestination;
    tsnConfig->CreateTSNSocket = CreateTSNLowSocket;
    tsnConfig->VlanId = appConfig.TsnLowVid;
    tsnConfig->VlanPCP = TSN_LOW_PCP_VALUE;
    tsnConfig->FrameIdRangeStart = 0x0200;
    tsnConfig->FrameIdRangeEnd = 0x03ff;

    return TsnThreadsCreate(tsnThreadContext, tsnConfig);
}

void TsnLowThreadsStop(struct ThreadContext *threadContext)
{
    TsnThreadsStop(threadContext, appConfig.TsnLowRxEnabled, appConfig.TsnLowTxEnabled);
}

void TsnLowThreadsFree(struct ThreadContext *threadContext)
{
    TsnThreadsFree(threadContext);
}

void TsnLowThreadsWaitForFinish(struct ThreadContext *threadContext)
{
    TsnThreadsWaitForFinish(threadContext, appConfig.TsnLowRxEnabled, appConfig.TsnLowTxEnabled);
}

int TsnHighThreadsCreate(struct ThreadContext *tsnThreadContext)
{
    struct TsnThreadConfiguration *tsnConfig;

    tsnConfig = malloc(sizeof(*tsnConfig));
    if (!tsnConfig)
        return -ENOMEM;

    memset(tsnConfig, '\0', sizeof(*tsnConfig));
    tsnConfig->FrameType = TSN_HIGH_FRAME_TYPE;
    tsnConfig->TsnSuffix = "High";
    tsnConfig->TsnTxEnabled = appConfig.TsnHighTxEnabled;
    tsnConfig->TsnRxEnabled = appConfig.TsnHighRxEnabled;
    tsnConfig->TsnRxMirrorEnabled = appConfig.TsnHighRxMirrorEnabled;
    tsnConfig->TsnXdpEnabled = appConfig.TsnHighXdpEnabled;
    tsnConfig->TsnXdpSkbMode = appConfig.TsnHighXdpSkbMode;
    tsnConfig->TsnXdpZcMode = appConfig.TsnHighXdpZcMode;
    tsnConfig->TsnXdpWakeupMode = appConfig.TsnHighXdpWakeupMode;
    tsnConfig->TsnXdpBusyPollMode = appConfig.TsnHighXdpBusyPollMode;
    tsnConfig->TsnTxTimeEnabled = appConfig.TsnHighTxTimeEnabled;
    tsnConfig->TsnIgnoreRxErrors = appConfig.TsnHighIgnoreRxErrors;
    tsnConfig->TsnTxTimeOffsetNS = appConfig.TsnHighTxTimeOffsetNS;
    tsnConfig->TsnNumFramesPerCycle = appConfig.TsnHighNumFramesPerCycle;
    tsnConfig->TsnPayloadPattern = appConfig.TsnHighPayloadPattern;
    tsnConfig->TsnPayloadPatternLength = appConfig.TsnHighPayloadPatternLength;
    tsnConfig->TsnFrameLength = appConfig.TsnHighFrameLength;
    tsnConfig->TsnSecurityMode = appConfig.TsnHighSecurityMode;
    tsnConfig->TsnSecurityAlgorithm = appConfig.TsnHighSecurityAlgorithm;
    tsnConfig->TsnSecurityKey = appConfig.TsnHighSecurityKey;
    tsnConfig->TsnSecurityKeyLength = appConfig.TsnHighSecurityKeyLength;
    tsnConfig->TsnSecurityIvPrefix = appConfig.TsnHighSecurityIvPrefix;
    tsnConfig->TsnSecurityIvPrefixLength = appConfig.TsnHighSecurityIvPrefixLength;
    tsnConfig->TsnRxQueue = appConfig.TsnHighRxQueue;
    tsnConfig->TsnTxQueue = appConfig.TsnHighTxQueue;
    tsnConfig->TsnSocketPriority = appConfig.TsnHighSocketPriority;
    tsnConfig->TsnTxThreadPriority = appConfig.TsnHighTxThreadPriority;
    tsnConfig->TsnRxThreadPriority = appConfig.TsnHighRxThreadPriority;
    tsnConfig->TsnTxThreadCpu = appConfig.TsnHighTxThreadCpu;
    tsnConfig->TsnRxThreadCpu = appConfig.TsnHighRxThreadCpu;
    tsnConfig->TsnInterface = appConfig.TsnHighInterface;
    tsnConfig->TsnDestination = appConfig.TsnHighDestination;
    tsnConfig->CreateTSNSocket = CreateTSNHighSocket;
    tsnConfig->VlanId = appConfig.TsnHighVid;
    tsnConfig->VlanPCP = TSN_HIGH_PCP_VALUE;
    tsnConfig->FrameIdRangeStart = 0x0100;
    tsnConfig->FrameIdRangeEnd = 0x01ff;

    return TsnThreadsCreate(tsnThreadContext, tsnConfig);
}

void TsnHighThreadsFree(struct ThreadContext *threadContext)
{
    TsnThreadsFree(threadContext);
}

void TsnHighThreadsStop(struct ThreadContext *threadContext)
{
    TsnThreadsStop(threadContext, appConfig.TsnHighRxEnabled, appConfig.TsnHighTxEnabled);
}

void TsnHighThreadsWaitForFinish(struct ThreadContext *threadContext)
{
    TsnThreadsWaitForFinish(threadContext, appConfig.TsnHighRxEnabled, appConfig.TsnHighTxEnabled);
}
