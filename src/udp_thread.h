/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _UDP_THREAD_H_
#define _UDP_THREAD_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pthread.h>

#include "thread.h"

#define UDP_TX_FRAME_LENGTH (4096)

struct UdpThreadConfiguration
{
    /* UDP configuration */
    const char *UdpSuffix;
    bool UdpTxEnabled;
    bool UdpRxEnabled;
    bool UdpTxGenEnabled;
    bool UdpRxMirrorEnabled;
    bool UdpIgnoreRxErrors;
    uint64_t UdpBurstPeriodNS;
    size_t UdpNumFramesPerCycle;
    const char *UdpPayloadPattern;
    size_t UdpPayloadPatternLength;
    size_t UdpFrameLength;
    int UdpSocketPriority;
    int UdpTxThreadPriority;
    int UdpRxThreadPriority;
    int UdpTxThreadCpu;
    int UdpRxThreadCpu;
    const char *UdpPort;
    const char *UdpDestination;
    const char *UdpSource;
    /* Corresponding stat functions */
    void (*StatUdpFrameSent)(uint64_t sequenceCounter);
    void (*StatUdpFrameReceived)(uint64_t sequenceCounter);
};

int UdpLowThreadsCreate(struct ThreadContext *threadContext);
void UdpLowThreadsStop(struct ThreadContext *threadContext);
void UdpLowThreadsFree(struct ThreadContext *threadContext);
void UdpLowThreadsWaitForFinish(struct ThreadContext *threadContext);

int UdpHighThreadsCreate(struct ThreadContext *threadContext);
void UdpHighThreadsStop(struct ThreadContext *threadContext);
void UdpHighThreadsFree(struct ThreadContext *threadContext);
void UdpHighThreadsWaitForFinish(struct ThreadContext *threadContext);

#endif /* _UDP_THREAD_H_ */
