/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _TSN_THREAD_H_
#define _TSN_THREAD_H_

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include <linux/if_ether.h>

#include "security.h"
#include "stat.h"
#include "thread.h"
#include "xdp.h"

#define TSN_TX_FRAME_LENGTH XDP_FRAME_SIZE

struct TsnThreadConfiguration
{
    /* TSN configuration */
    enum StatFrameType FrameType;
    const char *TsnSuffix;
    bool TsnTxEnabled;
    bool TsnRxEnabled;
    bool TsnRxMirrorEnabled;
    bool TsnXdpEnabled;
    bool TsnXdpSkbMode;
    bool TsnXdpZcMode;
    bool TsnXdpWakeupMode;
    bool TsnXdpBusyPollMode;
    bool TsnTxTimeEnabled;
    bool TsnIgnoreRxErrors;
    uint64_t TsnTxTimeOffsetNS;
    size_t TsnNumFramesPerCycle;
    const char *TsnPayloadPattern;
    size_t TsnPayloadPatternLength;
    size_t TsnFrameLength;
    enum SecurityMode TsnSecurityMode;
    enum SecurityAlgorithm TsnSecurityAlgorithm;
    char *TsnSecurityKey;
    size_t TsnSecurityKeyLength;
    char *TsnSecurityIvPrefix;
    size_t TsnSecurityIvPrefixLength;
    int TsnRxQueue;
    int TsnTxQueue;
    int TsnSocketPriority;
    int TsnTxThreadPriority;
    int TsnRxThreadPriority;
    int TsnTxThreadCpu;
    int TsnRxThreadCpu;
    const char *TsnInterface;
    const unsigned char *TsnDestination;
    /* Socket create function */
    int (*CreateTSNSocket)(void);
    /* TSN low/high specific */
    int VlanId;
    int VlanPCP;
    int FrameIdRangeStart;
    int FrameIdRangeEnd;
};

int TsnHighThreadsCreate(struct ThreadContext *threadContext);
void TsnHighThreadsStop(struct ThreadContext *threadContext);
void TsnHighThreadsFree(struct ThreadContext *threadContext);
void TsnHighThreadsWaitForFinish(struct ThreadContext *threadContext);

int TsnLowThreadsCreate(struct ThreadContext *threadContext);
void TsnLowThreadsStop(struct ThreadContext *threadContext);
void TsnLowThreadsFree(struct ThreadContext *threadContext);
void TsnLowThreadsWaitForFinish(struct ThreadContext *threadContext);

#endif /* _TSN_THREAD_H_ */
