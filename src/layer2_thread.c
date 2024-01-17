// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022,2023 Linutronix GmbH
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
#include <linux/if_packet.h>
#include <linux/if_vlan.h>

#include "config.h"
#include "layer2_thread.h"
#include "log.h"
#include "net.h"
#include "stat.h"
#include "thread.h"
#include "tx_time.h"
#include "utils.h"

static void GenericL2InitializeFrame(unsigned char *frameData, const unsigned char *source,
                                     const unsigned char *destination)
{
    struct VLANEthernetHeader *eth;
    struct GenericL2Header *l2;
    size_t payloadOffset;

    /*
     * GenericL2Frame:
     *   Destination
     *   Source
     *   VLAN tag
     *   Ether type
     *   Cycle counter
     *   Payload
     *   Padding to maxFrame
     */

    eth = (struct VLANEthernetHeader *)frameData;
    l2 = (struct GenericL2Header *)(frameData + sizeof(*eth));

    /* Ethernet header */
    memcpy(eth->Destination, destination, ETH_ALEN);
    memcpy(eth->Source, source, ETH_ALEN);

    /* VLAN Header */
    eth->VLANProto = htons(ETH_P_8021Q);
    eth->VLANTCI = htons(appConfig.GenericL2Vid | appConfig.GenericL2Pcp << VLAN_PCP_SHIFT);
    eth->VLANEncapsulatedProto = htons(appConfig.GenericL2EtherType);

    /* Generic L2 header */
    l2->MetaData.FrameCounter = 0;
    l2->MetaData.CycleCounter = 0;

    /* Payload */
    payloadOffset = sizeof(*eth) + sizeof(*l2);
    memcpy(frameData + payloadOffset, appConfig.GenericL2PayloadPattern, appConfig.GenericL2PayloadPatternLength);

    /* Padding: '\0' */
}

static void GenericL2InitializeFrames(unsigned char *frameData, size_t numFrames, const unsigned char *source,
                                      const unsigned char *destination)
{
    size_t i;

    for (i = 0; i < numFrames; ++i)
        GenericL2InitializeFrame(frameData + i * GENL2_TX_FRAME_LENGTH, source, destination);
}

static int GenericL2SendMessage(int socketFd, struct sockaddr_ll *destination, unsigned char *frameData,
                                size_t frameLength, uint64_t wakeupTime, uint64_t sequenceCounter, uint64_t duration)
{
    int ret;

    if (appConfig.GenericL2TxTimeEnabled)
    {
        /* Send message but with specified transmission time. */
        char control[CMSG_SPACE(sizeof(uint64_t))] = {0};
        struct cmsghdr *cmsg;
        struct msghdr msg;
        struct iovec iov;
        uint64_t txTime;

        txTime = TxTimeGetFrameTxTime(wakeupTime, sequenceCounter, duration, appConfig.GenericL2NumFramesPerCycle,
                                      appConfig.GenericL2TxTimeOffsetNS, "GenericL2");

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
        LogMessage(LOG_LEVEL_ERROR, "GenericL2Tx: send() for %" PRIu64 " failed: %s\n", sequenceCounter,
                   strerror(errno));
        return -errno;
    }

    return 0;
}

static void GenericL2SendFrame(unsigned char *frameData, size_t numFramesPerCycle, int socketFd,
                               struct sockaddr_ll *destination, uint64_t wakeupTime, uint64_t duration)
{
    struct VLANEthernetHeader *eth;
    struct GenericL2Header *l2;
    uint64_t sequenceCounter;
    ssize_t ret;

    /* Fetch meta data */
    l2 = (struct GenericL2Header *)(frameData + sizeof(*eth));
    sequenceCounter = MetaDataToSequenceCounter(&l2->MetaData, numFramesPerCycle);

    /* Send it */
    ret = GenericL2SendMessage(socketFd, destination, frameData, appConfig.GenericL2FrameLength, wakeupTime,
                               sequenceCounter, duration);
    if (ret)
        return;

    StatGenericL2FrameSent(sequenceCounter);
}

static void GenericL2GenAndSendFrame(unsigned char *frameData, size_t numFramesPerCycle, int socketFd,
                                     struct sockaddr_ll *destination, uint64_t wakeupTime, uint64_t sequenceCounter,
                                     uint64_t duration)
{
    struct VLANEthernetHeader *eth;
    struct GenericL2Header *l2;
    ssize_t ret;

    /* Adjust meta data */
    l2 = (struct GenericL2Header *)(frameData + sizeof(*eth));
    SequenceCounterToMetaData(&l2->MetaData, sequenceCounter, numFramesPerCycle);

    /* Send it */
    ret = GenericL2SendMessage(socketFd, destination, frameData, appConfig.GenericL2FrameLength, wakeupTime,
                               sequenceCounter, duration);
    if (ret)
        return;

    StatGenericL2FrameSent(sequenceCounter);
}

static void GenericL2GenAndSendXdpFrames(struct XdpSocket *xsk, size_t numFramesPerCycle, uint64_t sequenceCounter,
                                         uint32_t *frameNumber)
{
    uint32_t metaDataOffset = sizeof(struct VLANEthernetHeader) + offsetof(struct GenericL2Header, MetaData);
    struct XdpGenConfig xdp;

    xdp.Mode = SECURITY_MODE_NONE;
    xdp.SecurityContext = NULL;
    xdp.IvPrefix = NULL;
    xdp.PayloadPattern = NULL;
    xdp.PayloadPatternLength = 0;
    xdp.FrameLength = appConfig.GenericL2FrameLength;
    xdp.NumFramesPerCycle = numFramesPerCycle;
    xdp.FrameNumber = frameNumber;
    xdp.SequenceCounterBegin = sequenceCounter;
    xdp.MetaDataOffset = metaDataOffset;
    xdp.StatFunction = StatGenericL2FrameSent;

    XdpGenAndSendFrames(xsk, &xdp);
}

static void *GenericL2TxThreadRoutine(void *data)
{
    size_t receivedFramesLength = GENL2_TX_FRAME_LENGTH * appConfig.GenericL2NumFramesPerCycle;
    struct ThreadContext *threadContext = data;
    const long long cycleTimeNS = appConfig.ApplicationBaseCycleTimeNS;
    const bool mirrorEnabled = appConfig.GenericL2RxMirrorEnabled;
    unsigned char *receivedFrames = threadContext->RxFrameData;
    struct sockaddr_ll destination;
    unsigned char source[ETH_ALEN];
    struct timespec wakeupTime;
    uint64_t sequenceCounter = 0;
    unsigned int ifIndex;
    unsigned char *frame;
    uint32_t linkSpeed;
    uint64_t duration;
    int ret, socketFd;

    socketFd = threadContext->SocketFd;

    ret = GetInterfaceMacAddress(appConfig.GenericL2Interface, source, ETH_ALEN);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "GenericL2: Failed to get Source MAC address!\n");
        return NULL;
    }

    ret = GetInterfaceLinkSpeed(appConfig.GenericL2Interface, &linkSpeed);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "GenericL2Tx: Failed to get link speed!\n");
        return NULL;
    }

    ifIndex = if_nametoindex(appConfig.GenericL2Interface);
    if (!ifIndex)
    {
        LogMessage(LOG_LEVEL_ERROR, "GenericL2Tx: if_nametoindex() failed!\n");
        return NULL;
    }

    memset(&destination, '\0', sizeof(destination));
    destination.sll_family = PF_PACKET;
    destination.sll_ifindex = ifIndex;
    destination.sll_halen = ETH_ALEN;
    memcpy(destination.sll_addr, appConfig.GenericL2Destination, ETH_ALEN);

    duration = TxTimeGetFrameDuration(linkSpeed, appConfig.GenericL2FrameLength);

    frame = threadContext->TxFrameData;
    GenericL2InitializeFrame(frame, source, appConfig.GenericL2Destination);

    ret = GetThreadStartTime(appConfig.ApplicationTxBaseOffsetNS, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "GenericL2Tx: Failed to calculate thread start time: %s!\n", strerror(errno));
        return NULL;
    }

    while (!threadContext->Stop)
    {
        size_t i;

        IncrementPeriod(&wakeupTime, cycleTimeNS);

        do
        {
            ret = clock_nanosleep(appConfig.ApplicationClockId, TIMER_ABSTIME, &wakeupTime, NULL);
        } while (ret == EINTR);

        if (ret)
        {
            LogMessage(LOG_LEVEL_ERROR, "GenericL2Tx: clock_nanosleep() failed: %s\n", strerror(ret));
            return NULL;
        }

        if (!mirrorEnabled)
        {
            for (i = 0; i < appConfig.GenericL2NumFramesPerCycle; ++i)
                GenericL2GenAndSendFrame(frame, appConfig.GenericL2NumFramesPerCycle, socketFd, &destination,
                                         TsToNs(&wakeupTime), sequenceCounter++, duration);
        }
        else
        {
            size_t len;

            RingBufferFetch(threadContext->MirrorBuffer, receivedFrames, receivedFramesLength, &len);

            /* Len should be a multiple of frame size */
            for (i = 0; i < len / appConfig.GenericL2FrameLength; ++i)
                GenericL2SendFrame(receivedFrames + i * appConfig.GenericL2FrameLength,
                                   appConfig.GenericL2NumFramesPerCycle, socketFd, &destination, TsToNs(&wakeupTime),
                                   duration);
        }
    }

    return NULL;
}

static void *GenericL2XdpTxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    const long long cycleTimeNS = appConfig.ApplicationBaseCycleTimeNS;
    const bool mirrorEnabled = appConfig.GenericL2RxMirrorEnabled;
    uint32_t frameNumber = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    size_t numFrames = appConfig.GenericL2NumFramesPerCycle;
    unsigned char source[ETH_ALEN];
    struct timespec wakeupTime;
    uint64_t sequenceCounter = 0;
    unsigned char *frameData;
    struct XdpSocket *xsk;
    int ret;

    xsk = threadContext->Xsk;

    ret = GetInterfaceMacAddress(appConfig.GenericL2Interface, source, ETH_ALEN);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "GenericL2Tx: Failed to get Source MAC address!\n");
        return NULL;
    }

    /* First half of umem area is for Rx, the second half is for Tx. */
    frameData = xsk_umem__get_data(xsk->Umem.Buffer, XDP_FRAME_SIZE * XSK_RING_PROD__DEFAULT_NUM_DESCS);

    /* Initialize all Tx frames */
    GenericL2InitializeFrames(frameData, XSK_RING_CONS__DEFAULT_NUM_DESCS, source, appConfig.GenericL2Destination);

    ret = GetThreadStartTime(appConfig.ApplicationTxBaseOffsetNS, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "GenericL2Tx: Failed to calculate thread start time: %s!\n", strerror(errno));
        return NULL;
    }

    while (!threadContext->Stop)
    {
        IncrementPeriod(&wakeupTime, cycleTimeNS);

        do
        {
            ret = clock_nanosleep(appConfig.ApplicationClockId, TIMER_ABSTIME, &wakeupTime, NULL);
        } while (ret == EINTR);

        if (ret)
        {
            LogMessage(LOG_LEVEL_ERROR, "GenericL2Tx: clock_nanosleep() failed: %s\n", strerror(ret));
            return NULL;
        }

        if (!mirrorEnabled)
        {
            GenericL2GenAndSendXdpFrames(xsk, numFrames, sequenceCounter, &frameNumber);
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
                StatGenericL2FrameSent(i);

            xsk->OutstandingTx += received;
            threadContext->ReceivedFrames = 0;
            XdpCompleteTx(xsk);

            pthread_mutex_unlock(&threadContext->XdpDataMutex);
        }
    }

    return NULL;
}

static int GenericL2RxFrame(void *data, unsigned char *frameData, size_t len)
{
    struct ThreadContext *threadContext = data;
    const unsigned char *expectedPattern = (const unsigned char *)appConfig.GenericL2PayloadPattern;
    const size_t expectedPatternLength = appConfig.GenericL2PayloadPatternLength;
    const size_t numFramesPerCycle = appConfig.GenericL2NumFramesPerCycle;
    const bool mirrorEnabled = appConfig.GenericL2RxMirrorEnabled;
    const bool ignoreRxErrors = appConfig.GenericL2IgnoreRxErrors;
    size_t expectedFrameLength = appConfig.GenericL2FrameLength;
    unsigned char newFrame[GENL2_TX_FRAME_LENGTH];
    struct GenericL2Header *l2;
    uint64_t sequenceCounter;
    bool vlanTagMissing;
    void *p = frameData;
    struct ethhdr *eth;
    uint16_t proto;

    if (len < sizeof(struct VLANEthernetHeader))
    {
        LogMessage(LOG_LEVEL_WARNING, "GenericL2Rx: Too small frame received!\n");
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

    if (proto != htons(appConfig.GenericL2EtherType))
    {
        LogMessage(LOG_LEVEL_WARNING, "GenericL2Rx: Frame with wrong Ether Type received!\n");
        return -EINVAL;
    }

    /*
     * Check frame length: VLAN tag might be stripped or not. Check it.
     */
    if (len != expectedFrameLength)
    {
        LogMessage(LOG_LEVEL_WARNING, "GenericL2Rx: Frame with wrong length received!\n");
        return -EINVAL;
    }

    /*
     * Check cycle counter and payload.
     */
    l2 = p;
    p += sizeof(*l2);

    sequenceCounter = MetaDataToSequenceCounter(&l2->MetaData, numFramesPerCycle);

    StatGenericL2FrameReceived(sequenceCounter);

    if (sequenceCounter != threadContext->RxSequenceCounter)
    {
        if (!ignoreRxErrors)
            LogMessage(LOG_LEVEL_WARNING, "GenericL2Rx: frame[%" PRIu64 "] SequenceCounter mismatch: %" PRIu64 "!\n",
                       sequenceCounter, threadContext->RxSequenceCounter);
        threadContext->RxSequenceCounter++;
    }

    if (memcmp(p, expectedPattern, expectedPatternLength))
        LogMessage(LOG_LEVEL_WARNING, "GenericL2Rx: frame[%" PRIu64 "] Payload Pattern mismatch!\n", sequenceCounter);

    threadContext->RxSequenceCounter++;

    /*
     * If mirror enabled, assemble and store the frame for Tx later.
     *
     * In case of XDP the Rx umem area will be reused for Tx.
     */
    if (!mirrorEnabled)
        return 0;

    if (appConfig.GenericL2XdpEnabled)
    {
        /* Re-add vlan tag */
        if (vlanTagMissing)
            InsertVlanTag(frameData, len, appConfig.GenericL2Vid | appConfig.GenericL2Pcp << VLAN_PCP_SHIFT);

        /* Swap mac addresses inline */
        SwapMacAddresses(frameData, len);
    }
    else
    {
        /*
         * Build new frame for Tx with VLAN info.
         */
        BuildVLANFrameFromRx(frameData, len, newFrame, sizeof(newFrame), appConfig.GenericL2EtherType,
                             appConfig.GenericL2Vid | appConfig.GenericL2Pcp << VLAN_PCP_SHIFT);

        /*
         * Store the new frame.
         */
        RingBufferAdd(threadContext->MirrorBuffer, newFrame, len + 4);
    }

    return 0;
}

static void *GenericL2RxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    unsigned char frame[GENL2_TX_FRAME_LENGTH];
    int socketFd;

    socketFd = threadContext->SocketFd;

    while (!threadContext->Stop)
    {
        ssize_t len;

        len = recv(socketFd, frame, sizeof(frame), 0);
        if (len < 0)
        {
            LogMessage(LOG_LEVEL_ERROR, "GenericL2Rx: recv() failed: %s\n", strerror(errno));
            return NULL;
        }
        if (len == 0)
            return NULL;

        GenericL2RxFrame(threadContext, frame, len);
    }

    return NULL;
}

static void *GenericL2XdpRxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    const long long cycleTimeNS = appConfig.ApplicationBaseCycleTimeNS;
    const bool mirrorEnabled = appConfig.GenericL2RxMirrorEnabled;
    const size_t frameLength = appConfig.GenericL2FrameLength;
    struct XdpSocket *xsk = threadContext->Xsk;
    struct timespec wakeupTime;
    int ret;

    ret = GetThreadStartTime(appConfig.ApplicationRxBaseOffsetNS, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "GenericL2Rx: Failed to calculate thread start time: %s!\n", strerror(errno));
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
            LogMessage(LOG_LEVEL_ERROR, "GenericL2Rx: clock_nanosleep() failed: %s\n", strerror(ret));
            return NULL;
        }

        pthread_mutex_lock(&threadContext->XdpDataMutex);
        received = XdpReceiveFrames(xsk, frameLength, mirrorEnabled, GenericL2RxFrame, threadContext);
        threadContext->ReceivedFrames = received;
        pthread_mutex_unlock(&threadContext->XdpDataMutex);
    }

    return NULL;
}

struct ThreadContext *GenericL2ThreadsCreate(void)
{
    struct ThreadContext *threadContext;
    int ret;

    threadContext = malloc(sizeof(*threadContext));
    if (!threadContext)
        return NULL;

    memset(threadContext, '\0', sizeof(*threadContext));

    if (!CONFIG_IS_TRAFFIC_CLASS_ACTIVE(GenericL2))
        goto out;

    /*
     * For XDP the frames are stored in a umem area. That memory is part of
     * the socket.
     */
    if (!appConfig.GenericL2XdpEnabled)
    {
        threadContext->TxFrameData = calloc(appConfig.GenericL2NumFramesPerCycle, GENL2_TX_FRAME_LENGTH);
        if (!threadContext->TxFrameData)
        {
            fprintf(stderr, "Failed to allocate GenericL2TxFrameData\n");
            goto err_tx;
        }

        threadContext->RxFrameData = calloc(appConfig.GenericL2NumFramesPerCycle, GENL2_TX_FRAME_LENGTH);
        if (!threadContext->RxFrameData)
        {
            fprintf(stderr, "Failed to allocate GenericL2RxFrameData\n");
            goto err_rx;
        }
    }

    /*
     * For XDP a AF_XDP socket is allocated. Otherwise a Linux raw socket is
     * used.
     */
    if (appConfig.GenericL2XdpEnabled)
    {
        threadContext->SocketFd = 0;
        threadContext->Xsk =
            XdpOpenSocket(appConfig.GenericL2Interface, appConfig.ApplicationXdpProgram, appConfig.GenericL2RxQueue,
                          appConfig.GenericL2XdpSkbMode, appConfig.GenericL2XdpZcMode, appConfig.GenericL2XdpWakeupMode,
                          appConfig.GenericL2XdpBusyPollMode);
        if (!threadContext->Xsk)
        {
            fprintf(stderr, "Failed to create GenericL2 Xdp socket!\n");
            goto err_socket;
        }
    }
    else
    {
        threadContext->Xsk = NULL;
        threadContext->SocketFd = CreateGenericL2Socket();
        if (threadContext->SocketFd < 0)
        {
            fprintf(stderr, "Failed to create GenericL2 Socket!\n");
            goto err_socket;
        }
    }

    InitMutex(&threadContext->XdpDataMutex);

    /*
     * Same as above. For XDP the umem area is used.
     */
    if (appConfig.GenericL2RxMirrorEnabled && !appConfig.GenericL2XdpEnabled)
    {
        /*
         * Per period the expectation is: GenericL2NumFramesPerCycle * MAX_FRAME
         */
        threadContext->MirrorBuffer = RingBufferAllocate(GENL2_TX_FRAME_LENGTH * appConfig.GenericL2NumFramesPerCycle);
        if (!threadContext->MirrorBuffer)
        {
            fprintf(stderr, "Failed to allocate GenericL2 Mirror RingBuffer!\n");
            goto err_buffer;
        }
    }

    if (appConfig.GenericL2TxEnabled)
    {
        char threadName[128];

        snprintf(threadName, sizeof(threadName), "%sTxThread", appConfig.GenericL2Name);

        ret = CreateRtThread(
            &threadContext->TxTaskId, threadName, appConfig.GenericL2TxThreadPriority, appConfig.GenericL2TxThreadCpu,
            appConfig.GenericL2XdpEnabled ? GenericL2XdpTxThreadRoutine : GenericL2TxThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create GenericL2 Tx Thread!\n");
            goto err_thread;
        }
    }

    if (appConfig.GenericL2RxEnabled)
    {
        char threadName[128];

        snprintf(threadName, sizeof(threadName), "%sRxThread", appConfig.GenericL2Name);

        ret = CreateRtThread(
            &threadContext->RxTaskId, threadName, appConfig.GenericL2RxThreadPriority, appConfig.GenericL2RxThreadCpu,
            appConfig.GenericL2XdpEnabled ? GenericL2XdpRxThreadRoutine : GenericL2RxThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create GenericL2 Rx Thread!\n");
            goto err_thread_rx;
        }
    }

out:
    return threadContext;

err_thread_rx:
    if (threadContext->TxTaskId)
    {
        threadContext->Stop = 1;
        pthread_join(threadContext->TxTaskId, NULL);
    }
err_thread:
    RingBufferFree(threadContext->MirrorBuffer);
err_buffer:
    if (threadContext->SocketFd)
        close(threadContext->SocketFd);
    if (threadContext->Xsk)
        XdpCloseSocket(threadContext->Xsk, appConfig.GenericL2Interface, appConfig.GenericL2XdpSkbMode);
err_socket:
    free(threadContext->RxFrameData);
err_rx:
    free(threadContext->TxFrameData);
err_tx:
    free(threadContext);
    return NULL;
}

void GenericL2ThreadsFree(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    RingBufferFree(threadContext->MirrorBuffer);

    free(threadContext->TxFrameData);
    free(threadContext->RxFrameData);

    if (threadContext->SocketFd > 0)
        close(threadContext->SocketFd);

    if (threadContext->Xsk)
        XdpCloseSocket(threadContext->Xsk, appConfig.GenericL2Interface, appConfig.GenericL2XdpSkbMode);

    free(threadContext);
}

void GenericL2ThreadsStop(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    threadContext->Stop = 1;
    if (appConfig.GenericL2RxEnabled)
    {
        pthread_kill(threadContext->RxTaskId, SIGTERM);
        pthread_join(threadContext->RxTaskId, NULL);
    }
    if (appConfig.GenericL2TxEnabled)
        pthread_join(threadContext->TxTaskId, NULL);
}

void GenericL2ThreadsWaitForFinish(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    if (appConfig.GenericL2RxEnabled)
        pthread_join(threadContext->RxTaskId, NULL);
    if (appConfig.GenericL2TxEnabled)
        pthread_join(threadContext->TxTaskId, NULL);
}
