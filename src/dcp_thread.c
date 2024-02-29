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
#include "dcp_thread.h"
#include "log.h"
#include "net.h"
#include "security.h"
#include "stat.h"
#include "utils.h"

static void DcpBuildFrameFromRx(const unsigned char *oldFrame, size_t oldFrameLen, unsigned char *newFrame,
                                size_t newFrameLen, const unsigned char *source)
{
    struct VLANEthernetHeader *ethNew, *ethOld;

    /*
     * Two tasks:
     *  -> Keep destination and adjust source
     *  -> Inject VLAN header
     */

    if (newFrameLen < oldFrameLen + sizeof(struct VLANHeader))
        return;

    /* Copy payload */
    memcpy(newFrame + ETH_ALEN * 2 + sizeof(struct VLANHeader), oldFrame + ETH_ALEN * 2, oldFrameLen - ETH_ALEN * 2);

    /* Swap source destination */
    ethNew = (struct VLANEthernetHeader *)newFrame;
    ethOld = (struct VLANEthernetHeader *)oldFrame;

    memcpy(ethNew->Destination, ethOld->Destination, ETH_ALEN);
    memcpy(ethNew->Source, source, ETH_ALEN);

    /* Inject VLAN info */
    ethNew->VLANProto = htons(ETH_P_8021Q);
    ethNew->VLANTCI = htons(appConfig.DcpVid | DCP_PCP_VALUE << VLAN_PCP_SHIFT);
    ethNew->VLANEncapsulatedProto = htons(ETH_P_PROFINET_RT);
}

static void DcpSendFrame(const unsigned char *frameData, size_t frameLength, size_t numFramesPerCycle, int socketFd)
{
    struct VLANEthernetHeader *eth;
    struct ProfinetRtHeader *rt;
    uint64_t sequenceCounter;
    ssize_t ret;

    /* Fetch meta data */
    rt = (struct ProfinetRtHeader *)(frameData + sizeof(*eth));
    sequenceCounter = MetaDataToSequenceCounter(&rt->MetaData, numFramesPerCycle);

    /* Send it */
    ret = send(socketFd, frameData, frameLength, 0);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "DcpTx: send() for %" PRIu64 " failed: %s\n", sequenceCounter, strerror(errno));
        return;
    }

    StatFrameSent(DCP_FRAME_TYPE, sequenceCounter);
}

static void DcpGenAndSendFrame(unsigned char *frameData, size_t frameLength, size_t numFramesPerCycle, int socketFd,
                               uint64_t sequenceCounter)
{
    struct VLANEthernetHeader *eth;
    struct ProfinetRtHeader *rt;
    ssize_t ret;

    /* Adjust meta data */
    rt = (struct ProfinetRtHeader *)(frameData + sizeof(*eth));
    SequenceCounterToMetaData(&rt->MetaData, sequenceCounter, numFramesPerCycle);

    /* Send it */
    ret = send(socketFd, frameData, frameLength, 0);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "DcpTx: send() for %" PRIu64 " failed: %s\n", sequenceCounter, strerror(errno));
        return;
    }

    StatFrameSent(DCP_FRAME_TYPE, sequenceCounter);
}

static void *DcpTxThreadRoutine(void *data)
{
    unsigned char receivedFrames[DCP_TX_FRAME_LENGTH * appConfig.DcpNumFramesPerCycle];
    const bool mirrorEnabled = appConfig.DcpRxMirrorEnabled;
    struct ThreadContext *threadContext = data;
    unsigned char source[ETH_ALEN];
    uint64_t sequenceCounter = 0;
    unsigned char *frame;
    int ret, socketFd;
    pthread_mutex_t *mutex = &threadContext->DataMutex;
    pthread_cond_t *cond = &threadContext->DataCondVar;

    socketFd = threadContext->SocketFd;

    ret = GetInterfaceMacAddress(appConfig.DcpInterface, source, ETH_ALEN);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "DcpTx: Failed to get Source MAC address!\n");
        return NULL;
    }

    frame = threadContext->TxFrameData;
    InitializeProfinetFrame(SECURITY_MODE_NONE, frame, DCP_TX_FRAME_LENGTH, source, appConfig.DcpDestination,
                            appConfig.DcpPayloadPattern, appConfig.DcpPayloadPatternLength,
                            appConfig.DcpVid | DCP_PCP_VALUE << VLAN_PCP_SHIFT, 0xfefe);

    while (!threadContext->Stop)
    {
        size_t numFrames, i;

        /*
         * Wait until signalled. These DCP frames have to be sent after
         * the RTA frames. Therefore, the RTA TxThread signals this one
         * here.
         */
        pthread_mutex_lock(mutex);
        pthread_cond_wait(cond, mutex);
        numFrames = threadContext->NumFramesAvailable;
        threadContext->NumFramesAvailable = 0;
        pthread_mutex_unlock(mutex);

        /*
         * Send DcpFrames, two possibilites:
         *  a) Generate it, or
         *  b) Use received ones if mirror enabled
         */
        if (!mirrorEnabled)
        {
            /* Send DcpFrames */
            for (i = 0; i < numFrames; ++i)
                DcpGenAndSendFrame(frame, appConfig.DcpFrameLength, appConfig.DcpNumFramesPerCycle, socketFd,
                                   sequenceCounter++);
        }
        else
        {
            size_t len;

            RingBufferFetch(threadContext->MirrorBuffer, receivedFrames, sizeof(receivedFrames), &len);

            /* Len should be a multiple of frame size */
            for (i = 0; i < len / appConfig.DcpFrameLength; ++i)
                DcpSendFrame(receivedFrames + i * appConfig.DcpFrameLength, appConfig.DcpFrameLength,
                             appConfig.DcpNumFramesPerCycle, socketFd);

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

static int DcpRxFrame(struct ThreadContext *threadContext, unsigned char *frameData, size_t len)
{
    const unsigned char *expectedPattern = (const unsigned char *)appConfig.DcpPayloadPattern;
    const size_t expectedPatternLength = appConfig.DcpPayloadPatternLength;
    const size_t numFramesPerCycle = appConfig.DcpNumFramesPerCycle;
    const bool mirrorEnabled = appConfig.DcpRxMirrorEnabled;
    const bool ignoreRxErrors = appConfig.DcpIgnoreRxErrors;
    const size_t frameLength = appConfig.DcpFrameLength;
    bool outOfOrder, payloadMismatch, frameIdMismatch;
    unsigned char newFrame[DCP_TX_FRAME_LENGTH];
    struct ProfinetRtHeader *rt;
    uint64_t sequenceCounter;

    if (len != frameLength - 4)
    {
        LogMessage(LOG_LEVEL_ERROR, "DcpRx: Frame with wrong length received!\n");
        return -EINVAL;
    }

    /*
     * Check cycle counter and payload. The frame id range is checked by the
     * attached BPF filter.
     */
    rt = (struct ProfinetRtHeader *)(frameData + sizeof(struct ethhdr));
    sequenceCounter = MetaDataToSequenceCounter(&rt->MetaData, numFramesPerCycle);

    outOfOrder = sequenceCounter != threadContext->RxSequenceCounter;
    payloadMismatch = memcmp(frameData + sizeof(struct ethhdr) + sizeof(*rt), expectedPattern, expectedPatternLength);
    frameIdMismatch = false;

    StatFrameReceived(DCP_FRAME_TYPE, sequenceCounter, outOfOrder, payloadMismatch, frameIdMismatch);

    if (outOfOrder)
    {
        if (!ignoreRxErrors)
            LogMessage(LOG_LEVEL_WARNING, "DcpRx: frame[%" PRIu64 "] SequenceCounter mismatch: %" PRIu64 "!\n",
                       sequenceCounter, threadContext->RxSequenceCounter);
        threadContext->RxSequenceCounter++;
    }

    if (payloadMismatch)
        LogMessage(LOG_LEVEL_WARNING, "DcpRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n", sequenceCounter);

    threadContext->RxSequenceCounter++;

    /*
     * If mirror enabled, assemble and store the frame for Tx later.
     */
    if (!mirrorEnabled)
        return 0;

    /*
     * Build new frame for Tx with VLAN info.
     */
    DcpBuildFrameFromRx(frameData, len, newFrame, sizeof(newFrame), threadContext->Source);

    /*
     * Store the new frame.
     */
    RingBufferAdd(threadContext->MirrorBuffer, newFrame, len + sizeof(struct VLANHeader));

    pthread_mutex_lock(&threadContext->DataMutex);
    threadContext->NumFramesAvailable++;
    pthread_mutex_unlock(&threadContext->DataMutex);

    return 0;
}

static void *DcpRxThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    unsigned char frame[DCP_TX_FRAME_LENGTH];
    int socketFd;

    socketFd = threadContext->SocketFd;

    while (!threadContext->Stop)
    {
        ssize_t len;

        /* Wait for DCP frame */
        len = recv(socketFd, frame, sizeof(frame), 0);
        if (len < 0)
        {
            LogMessage(LOG_LEVEL_ERROR, "DcpRx: recv() failed: %s\n", strerror(errno));
            return NULL;
        }
        if (len == 0)
            return NULL;

        DcpRxFrame(threadContext, frame, len);
    }

    return NULL;
}

static void *DcpTxGenerationThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    pthread_mutex_t *mutex = &threadContext->DataMutex;
    uint64_t cycleTimeNS = appConfig.DcpBurstPeriodNS;
    uint64_t numFrames = appConfig.DcpNumFramesPerCycle;
    struct timespec wakeupTime;
    int ret;

    /*
     * The DCP frames are generated by bursts with a certain period. This
     * thread is responsible for generating it.
     */

    ret = GetThreadStartTime(0, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "DcpTxGen: Failed to calculate thread start time: %s!\n", strerror(errno));
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
            LogMessage(LOG_LEVEL_ERROR, "DcpTxGen: clock_nanosleep() failed: %s\n", strerror(ret));
            return NULL;
        }

        /* Generate frames */
        pthread_mutex_lock(mutex);
        threadContext->NumFramesAvailable = numFrames;
        pthread_mutex_unlock(mutex);
    }

    return NULL;
}

int DcpThreadsCreate(struct ThreadContext *threadContext)
{
    int ret;

    if (!CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Dcp))
        goto out;

    threadContext->SocketFd = CreateDCPSocket();
    if (threadContext->SocketFd < 0)
    {
        fprintf(stderr, "Failed to create DcpSocket!\n");
        ret = -ENOMEM;
        goto err;
    }

    InitMutex(&threadContext->DataMutex);
    InitConditionVariable(&threadContext->DataCondVar);

    threadContext->TxFrameData = calloc(1, DCP_TX_FRAME_LENGTH);
    if (!threadContext->TxFrameData)
    {
        fprintf(stderr, "Failed to allocate Dcp TxFrameData!\n");
        ret = -ENOMEM;
        goto err_tx;
    }

    ret = GetInterfaceMacAddress(appConfig.DcpInterface, threadContext->Source, sizeof(threadContext->Source));
    if (ret < 0)
    {
        fprintf(stderr, "Failed to get Dcp Source MAC address!\n");
        goto err_mac;
    }

    if (appConfig.DcpRxMirrorEnabled)
    {
        /*
         * Per period the expectation is: DcpNumFramesPerCycle * MAX_FRAME
         */
        threadContext->MirrorBuffer = RingBufferAllocate(DCP_TX_FRAME_LENGTH * appConfig.DcpNumFramesPerCycle);
        if (!threadContext->MirrorBuffer)
        {
            fprintf(stderr, "Failed to allocate Dcp Mirror RingBuffer!\n");
            ret = -ENOMEM;
            goto err_mac;
        }
    }

    ret = CreateRtThread(&threadContext->TxTaskId, "DcpTxThread", appConfig.DcpTxThreadPriority,
                         appConfig.DcpTxThreadCpu, DcpTxThreadRoutine, threadContext);
    if (ret)
    {
        fprintf(stderr, "Failed to create Dcp Tx Thread!\n");
        goto err_thread;
    }

    ret = CreateRtThread(&threadContext->TxGenTaskId, "DcpTxGenThread", appConfig.DcpTxThreadPriority,
                         appConfig.DcpTxThreadCpu, DcpTxGenerationThreadRoutine, threadContext);
    if (ret)
    {
        fprintf(stderr, "Failed to create Dcp Tx Thread!\n");
        goto err_thread_txgen;
    }

    ret = CreateRtThread(&threadContext->RxTaskId, "DcpRxThread", appConfig.DcpRxThreadPriority,
                         appConfig.DcpRxThreadCpu, DcpRxThreadRoutine, threadContext);
    if (ret)
    {
        fprintf(stderr, "Failed to create Dcp Rx Thread!\n");
        goto err_thread_rx;
    }

out:
    return 0;

err_thread_rx:
    threadContext->Stop = 1;
    pthread_join(threadContext->TxGenTaskId, NULL);
err_thread_txgen:
    threadContext->Stop = 1;
    pthread_join(threadContext->TxTaskId, NULL);
err_thread:
    RingBufferFree(threadContext->MirrorBuffer);
err_mac:
    free(threadContext->TxFrameData);
err_tx:
    close(threadContext->SocketFd);
err:
    return ret;
}

void DcpThreadsFree(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    RingBufferFree(threadContext->MirrorBuffer);

    if (threadContext->SocketFd > 0)
        close(threadContext->SocketFd);
}

void DcpThreadsStop(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    threadContext->Stop = 1;

    pthread_kill(threadContext->RxTaskId, SIGTERM);

    pthread_join(threadContext->RxTaskId, NULL);
    pthread_join(threadContext->TxTaskId, NULL);
    pthread_join(threadContext->TxGenTaskId, NULL);
}

void DcpThreadsWaitForFinish(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    pthread_join(threadContext->RxTaskId, NULL);
    pthread_join(threadContext->TxTaskId, NULL);
    pthread_join(threadContext->TxGenTaskId, NULL);
}
