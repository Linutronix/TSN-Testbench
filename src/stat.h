/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _STAT_H_
#define _STAT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum StatFrameType
{
    TSN_HIGH_FRAME_TYPE = 0,
    TSN_LOW_FRAME_TYPE,
    RTC_FRAME_TYPE,
    RTA_FRAME_TYPE,
    DCP_FRAME_TYPE,
    LLDP_FRAME_TYPE,
    UDP_HIGH_FRAME_TYPE,
    UDP_LOW_FRAME_TYPE,
    GENERICL2_FRAME_TYPE,
    NUM_FRAME_TYPES,
};

static inline bool StatFrameTypeIsRealTime(enum StatFrameType frameType)
{
    switch (frameType)
    {
    case TSN_HIGH_FRAME_TYPE:
    case TSN_LOW_FRAME_TYPE:
    case RTC_FRAME_TYPE:
    case GENERICL2_FRAME_TYPE:
        return true;
    default:
        return false;
    }
}

struct Statistics
{
    uint64_t FramesSent;
    uint64_t FramesReceived;
    uint64_t OutOfOrderErrors;
    uint64_t FrameIdErrors;
    uint64_t PayloadErrors;
    uint64_t RoundTripMin;
    uint64_t RoundTripMax;
    uint64_t RoundTripCount;
    uint64_t RoundTripOutliers;
    double RoundTripSum;
    double RoundTripAvg;
};
extern struct Statistics GlobalStatistics[NUM_FRAME_TYPES];

struct RoundTripContext
{
    int64_t *Backlog;
    size_t BacklogLen;
};
extern struct RoundTripContext RoundTripContexts[NUM_FRAME_TYPES];

int StatInit(bool logRtt);
void StatFree(void);
void StatFrameSent(enum StatFrameType frameType, uint64_t cycleNumber);
void StatFrameReceived(enum StatFrameType frameType, uint64_t cycleNumber, bool outOfOrder, bool payloadMismatch,
                       bool frameIdMismatch);

#endif /* _STAT_H_ */
