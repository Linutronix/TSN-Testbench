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

#include "config.h"
#include "lldp_thread.h"
#include "log.h"
#include "net.h"
#include "net_def.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

static void LldpBuildFrameFromRx(unsigned char *frameData, const unsigned char *source)
{
    struct ethhdr *eth = (struct ethhdr *)frameData;

    /*
     * One task: Swap source.
     */

    memcpy(eth->h_source, source, ETH_ALEN);
}

static void LldpInitializeFrame(unsigned char *frameData, const unsigned char *source, const unsigned char *destination)
{
    struct ReferenceMetaData *meta;
    size_t payloadOffset;
    struct ethhdr *eth;

    /*
     * LldpFrame:
     *   Destination (multicast)
     *   Source
     *   Ether type: 88cc
     *   Cycle counter
     *   Payload
     *   Padding to maxFrame
     */

    eth = (struct ethhdr *)frameData;

    /* Ethernet header */
    memcpy(eth->h_dest, destination, ETH_ALEN);
    memcpy(eth->h_source, source, ETH_ALEN);
    eth->h_proto = htons(ETH_P_LLDP);

    /* Payload: SequenceCounter + Data */
    meta = (struct ReferenceMetaData *)(frameData + sizeof(*eth));
    memset(meta, '\0', sizeof(*meta));
    payloadOffset = sizeof(*eth) + sizeof(*meta);
    memcpy(frameData + payloadOffset, appConfig.LldpPayloadPattern, appConfig.LldpPayloadPatternLength);

    /* Padding: '\0' */
}

static void LldpSendFrame(const unsigned char *frameData, size_t frameLength, size_t numFramesPerCycle, int socketFd)
{
    struct ReferenceMetaData *meta;
    uint64_t sequenceCounter;
    struct ethhdr *eth;
    ssize_t ret;

    /* Fetch meta data */
    meta = (struct ReferenceMetaData *)(frameData + sizeof(*eth));
    sequenceCounter = MetaDataToSequenceCounter(meta, numFramesPerCycle);

    /* Send it */
    ret = send(socketFd, frameData, frameLength, 0);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "LldpTx: send() for %" PRIu64 " failed: %s\n", sequenceCounter, strerror(errno));
        return;
    }

    StatFrameSent(LLDP_FRAME_TYPE, sequenceCounter);
}

static void LldpGenAndSendFrame(unsigned char *frameData, size_t frameLength, size_t numFramesPerCycle, int socketFd,
                                uint64_t sequenceCounter)
{
    struct ReferenceMetaData *meta;
    struct ethhdr *eth;
    ssize_t ret;

    /* Adjust meta data */
    meta = (struct ReferenceMetaData *)(frameData + sizeof(*eth));
    SequenceCounterToMetaData(meta, sequenceCounter, numFramesPerCycle);

    /* Send it */
    ret = send(socketFd, frameData, frameLength, 0);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "LldpTx: send() for %" PRIu64 " failed: %s\n", sequenceCounter, strerror(errno));
        return;
    }

    StatFrameSent(LLDP_FRAME_TYPE, sequenceCounter);
}

static void *LldpTxThreadRoutine(void *data)
{
    unsigned char receivedFrames[LLDP_TX_FRAME_LENGTH * appConfig.LldpNumFramesPerCycle];
    const bool mirrorEnabled = appConfig.LldpRxMirrorEnabled;
    struct ThreadContext *threadContext = data;
    unsigned char source[ETH_ALEN];
    uint64_t sequenceCounter = 0;
    unsigned char *frame;
    int ret, socketFd;
    pthread_mutex_t *mutex = &threadContext->DataMutex;
    pthread_cond_t *cond = &threadContext->DataCondVar;

    socketFd = threadContext->SocketFd;

    ret = GetInterfaceMacAddress(appConfig.LldpInterface, source, ETH_ALEN);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "LldpTx: Failed to get Source MAC address!\n");
        return NULL;
    }

    frame = threadContext->TxFrameData;
    LldpInitializeFrame(frame, source, appConfig.LldpDestination);

    while (!threadContext->Stop)
    {
        size_t numFrames, i;

        /*
         * Wait until signalled. These LLDP frames have to be sent after
         * the DCP frames. Therefore, the DCP TxThread signals this one
         * here.
         */
        pthread_mutex_lock(mutex);
        pthread_cond_wait(cond, mutex);
        numFrames = threadContext->NumFramesAvailable;
        threadContext->NumFramesAvailable = 0;
        pthread_mutex_unlock(mutex);

        /*
         * Send LldpFrames, two possibilites:
         *  a) Generate it, or
         *  b) Use received ones if mirror enabled
         */
        if (!mirrorEnabled)
        {
            /* Send LldpFrames */
            for (i = 0; i < numFrames; ++i)
                LldpGenAndSendFrame(frame, appConfig.LldpFrameLength, appConfig.LldpNumFramesPerCycle, socketFd,
                                    sequenceCounter++);
        }
        else
        {
            size_t len;

            RingBufferFetch(threadContext->MirrorBuffer, receivedFrames, sizeof(receivedFrames), &len);

            /* Len should be a multiple of frame size */
            for (i = 0; i < len / appConfig.LldpFrameLength; ++i)
                LldpSendFrame(receivedFrames + i * appConfig.LldpFrameLength, appConfig.LldpFrameLength,
                              appConfig.LldpNumFramesPerCycle, socketFd);

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

static void *LldpRxThreadRoutine(void *data)
{
    const unsigned char *expectedPattern = (const unsigned char *)appConfig.LldpPayloadPattern;
    const size_t expectedPatternLength = appConfig.LldpPayloadPatternLength;
    const size_t numFramesPerCycle = appConfig.LldpNumFramesPerCycle;
    const bool mirrorEnabled = appConfig.LldpRxMirrorEnabled;
    const bool ignoreRxErrors = appConfig.LldpIgnoreRxErrors;
    const ssize_t frameLength = appConfig.LldpFrameLength;
    unsigned char frame[LLDP_TX_FRAME_LENGTH], source[ETH_ALEN];
    struct ThreadContext *threadContext = data;
    uint64_t sequenceCounter = 0;
    int socketFd, ret;

    socketFd = threadContext->SocketFd;

    ret = GetInterfaceMacAddress(appConfig.LldpInterface, source, ETH_ALEN);
    if (ret < 0)
    {
        LogMessage(LOG_LEVEL_ERROR, "LldpTx: Failed to get Source MAC address!\n");
        return NULL;
    }

    while (!threadContext->Stop)
    {
        bool outOfOrder, payloadMismatch, frameIdMismatch;
        struct ReferenceMetaData *meta;
        uint64_t rxSequenceCounter;
        ssize_t len;

        /* Wait for LLDP frame */
        len = recv(socketFd, frame, sizeof(frame), 0);
        if (len < 0)
        {
            LogMessage(LOG_LEVEL_ERROR, "LldpRx: recv() failed: %s\n", strerror(errno));
            return NULL;
        }
        if (len == 0)
            return NULL;

        if (len != frameLength)
        {
            LogMessage(LOG_LEVEL_WARNING, "LldpRx: Frame with wrong length received!\n");
            continue;
        }

        /*
         * Check cycle counter and payload. The ether type is checked by
         * the attached BPF filter.
         */
        meta = (struct ReferenceMetaData *)(frame + sizeof(struct ethhdr));
        rxSequenceCounter = MetaDataToSequenceCounter(meta, numFramesPerCycle);

        outOfOrder = sequenceCounter != threadContext->RxSequenceCounter;
        payloadMismatch =
            memcmp(frame + sizeof(struct ethhdr) + sizeof(rxSequenceCounter), expectedPattern, expectedPatternLength);
        frameIdMismatch = false;

        StatFrameReceived(LLDP_FRAME_TYPE, rxSequenceCounter, outOfOrder, payloadMismatch, frameIdMismatch);

        if (outOfOrder)
        {
            if (!ignoreRxErrors)
                LogMessage(LOG_LEVEL_WARNING, "LldpRx: frame[%" PRIu64 "] SequenceCounter mismatch: %" PRIu64 "!\n",
                           rxSequenceCounter, sequenceCounter);
            sequenceCounter++;
        }

        if (payloadMismatch)
            LogMessage(LOG_LEVEL_WARNING, "LldpRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n", rxSequenceCounter);

        sequenceCounter++;

        /*
         * If mirror enabled, assemble and store the frame for Tx later.
         */
        if (!mirrorEnabled)
            continue;

        /*
         * Build new frame for Tx without VLAN info.
         */
        LldpBuildFrameFromRx(frame, source);

        /*
         * Store the new frame.
         */
        RingBufferAdd(threadContext->MirrorBuffer, frame, len);

        pthread_mutex_lock(&threadContext->DataMutex);
        threadContext->NumFramesAvailable++;
        pthread_mutex_unlock(&threadContext->DataMutex);
    }

    return NULL;
}

static void *LldpTxGenerationThreadRoutine(void *data)
{
    struct ThreadContext *threadContext = data;
    pthread_mutex_t *mutex = &threadContext->DataMutex;
    uint64_t cycleTimeNS = appConfig.LldpBurstPeriodNS;
    uint64_t numFrames = appConfig.LldpNumFramesPerCycle;
    struct timespec wakeupTime;
    int ret;

    /*
     * The LLDP frames are generated by bursts with a certain period. This
     * thread is responsible for generating it.
     */

    ret = GetThreadStartTime(0, &wakeupTime);
    if (ret)
    {
        LogMessage(LOG_LEVEL_ERROR, "LldpTxGen: Failed to calculate thread start time: %s!\n", strerror(errno));
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
            LogMessage(LOG_LEVEL_ERROR, "LldpTxGen: clock_nanosleep() failed: %s\n", strerror(ret));
            return NULL;
        }

        /* Generate frames */
        pthread_mutex_lock(mutex);
        threadContext->NumFramesAvailable = numFrames;
        pthread_mutex_unlock(mutex);
    }

    return NULL;
}

int LldpThreadsCreate(struct ThreadContext *threadContext)
{
    int ret;

    if (!CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Lldp))
        goto out;

    threadContext->SocketFd = CreateLLDPSocket();
    if (threadContext->SocketFd < 0)
    {
        fprintf(stderr, "Failed to create LldpSocket!\n");
        ret = -errno;
        goto err;
    }

    InitMutex(&threadContext->DataMutex);
    InitConditionVariable(&threadContext->DataCondVar);

    threadContext->TxFrameData = calloc(1, LLDP_TX_FRAME_LENGTH);
    if (!threadContext->TxFrameData)
    {
        fprintf(stderr, "Failed to allocate Lldp TxFrameData!\n");
        ret = -ENOMEM;
        goto err_tx;
    }

    if (appConfig.LldpRxMirrorEnabled)
    {
        /*
         * Per period the expectation is: LldpNumFramesPerCycle * MAX_FRAME
         */
        threadContext->MirrorBuffer = RingBufferAllocate(LLDP_TX_FRAME_LENGTH * appConfig.LldpNumFramesPerCycle);
        if (!threadContext->MirrorBuffer)
        {
            fprintf(stderr, "Failed to allocate Lldp Mirror RingBuffer!\n");
            ret = -ENOMEM;
            goto err_buffer;
        }
    }

    if (appConfig.LldpTxEnabled)
    {
        ret = CreateRtThread(&threadContext->TxTaskId, "LldpTxThread", appConfig.LldpTxThreadPriority,
                             appConfig.LldpTxThreadCpu, LldpTxThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create Lldp Tx Thread!\n");
            goto err_thread;
        }
    }

    if (appConfig.LldpTxGenEnabled)
    {
        ret = CreateRtThread(&threadContext->TxGenTaskId, "LldpTxGenThread", appConfig.LldpTxThreadPriority,
                             appConfig.LldpTxThreadCpu, LldpTxGenerationThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create Lldp Tx Thread!\n");
            goto err_thread_txgen;
        }
    }

    if (appConfig.LldpRxEnabled)
    {
        ret = CreateRtThread(&threadContext->RxTaskId, "LldpRxThread", appConfig.LldpRxThreadPriority,
                             appConfig.LldpRxThreadCpu, LldpRxThreadRoutine, threadContext);
        if (ret)
        {
            fprintf(stderr, "Failed to create Lldp Rx Thread!\n");
            goto err_thread_rx;
        }
    }

out:
    ret = 0;

    return ret;

err_thread_rx:
    if (appConfig.LldpTxGenEnabled)
    {
        threadContext->Stop = 1;
        pthread_join(threadContext->TxGenTaskId, NULL);
    }
err_thread_txgen:
    if (appConfig.LldpTxEnabled)
    {
        threadContext->Stop = 1;
        pthread_join(threadContext->TxTaskId, NULL);
    }
err_thread:
    RingBufferFree(threadContext->MirrorBuffer);
err_buffer:
    free(threadContext->TxFrameData);
err_tx:
    close(threadContext->SocketFd);
err:
    return ret;
}

void LldpThreadsFree(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    RingBufferFree(threadContext->MirrorBuffer);

    if (threadContext->SocketFd > 0)
        close(threadContext->SocketFd);
}

void LldpThreadsStop(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    threadContext->Stop = 1;
    if (appConfig.LldpRxEnabled)
    {
        pthread_kill(threadContext->RxTaskId, SIGTERM);
        pthread_join(threadContext->RxTaskId, NULL);
    }
    if (appConfig.LldpTxEnabled)
        pthread_join(threadContext->TxTaskId, NULL);
    if (appConfig.LldpTxGenEnabled)
        pthread_join(threadContext->TxGenTaskId, NULL);
}

void LldpThreadsWaitForFinish(struct ThreadContext *threadContext)
{
    if (!threadContext)
        return;

    if (appConfig.LldpRxEnabled)
        pthread_join(threadContext->RxTaskId, NULL);
    if (appConfig.LldpTxEnabled)
        pthread_join(threadContext->TxTaskId, NULL);
    if (appConfig.LldpTxGenEnabled)
        pthread_join(threadContext->TxGenTaskId, NULL);
}
