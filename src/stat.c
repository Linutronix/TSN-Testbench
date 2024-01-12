// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <inttypes.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "config.h"
#include "log.h"
#include "stat.h"
#include "utils.h"

struct Statistics GlobalStatistics[NUM_FRAME_TYPES];
struct RoundTripContext RoundTripContexts[NUM_FRAME_TYPES];
static uint64_t RttExpectedRTLimit;
static bool LogRtt;
static FILE *FileTracingOn;
static FILE *FileTraceMarker;

static const char *StatFrameTypeNames[NUM_FRAME_TYPES] = {"TsnHigh", "TsnLow",  "Rtc",    "Rta",      "Dcp",
                                                          "Lldp",    "UdpHigh", "UdpLow", "GenericL2"};

static inline const char *StatFrameTypeToString(enum StatFrameType frameType)
{
    return StatFrameTypeNames[frameType];
}

/*
 * Keep 2048 periods of backlog available. If a frame is received later than
 * 2048 periods after sending, it's a bug in any case.
 *
 * E.g. A period of 500us results in a backlog of 1s.
 */
#define STAT_MAX_BACKLOG 2048

int StatInit(bool logRtt)
{
    RoundTripContexts[TSN_HIGH_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.TsnHighNumFramesPerCycle;
    RoundTripContexts[TSN_LOW_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.TsnLowNumFramesPerCycle;
    RoundTripContexts[RTC_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.RtcNumFramesPerCycle;
    RoundTripContexts[RTA_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.RtaNumFramesPerCycle;
    RoundTripContexts[DCP_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.DcpNumFramesPerCycle;
    RoundTripContexts[LLDP_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.LldpNumFramesPerCycle;
    RoundTripContexts[UDP_HIGH_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.UdpHighNumFramesPerCycle;
    RoundTripContexts[UDP_LOW_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.UdpLowNumFramesPerCycle;
    RoundTripContexts[GENERICL2_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.GenericL2NumFramesPerCycle;

    RoundTripContexts[TSN_HIGH_FRAME_TYPE].Backlog =
        calloc(RoundTripContexts[TSN_HIGH_FRAME_TYPE].BacklogLen, sizeof(int64_t));
    RoundTripContexts[TSN_LOW_FRAME_TYPE].Backlog =
        calloc(RoundTripContexts[TSN_LOW_FRAME_TYPE].BacklogLen, sizeof(int64_t));
    RoundTripContexts[RTC_FRAME_TYPE].Backlog = calloc(RoundTripContexts[RTC_FRAME_TYPE].BacklogLen, sizeof(int64_t));
    RoundTripContexts[RTA_FRAME_TYPE].Backlog = calloc(RoundTripContexts[RTA_FRAME_TYPE].BacklogLen, sizeof(int64_t));
    RoundTripContexts[DCP_FRAME_TYPE].Backlog = calloc(RoundTripContexts[DCP_FRAME_TYPE].BacklogLen, sizeof(int64_t));
    RoundTripContexts[LLDP_FRAME_TYPE].Backlog = calloc(RoundTripContexts[LLDP_FRAME_TYPE].BacklogLen, sizeof(int64_t));
    RoundTripContexts[UDP_HIGH_FRAME_TYPE].Backlog =
        calloc(RoundTripContexts[UDP_HIGH_FRAME_TYPE].BacklogLen, sizeof(int64_t));
    RoundTripContexts[UDP_LOW_FRAME_TYPE].Backlog =
        calloc(RoundTripContexts[UDP_LOW_FRAME_TYPE].BacklogLen, sizeof(int64_t));
    RoundTripContexts[GENERICL2_FRAME_TYPE].Backlog =
        calloc(RoundTripContexts[GENERICL2_FRAME_TYPE].BacklogLen, sizeof(int64_t));

    if (!RoundTripContexts[TSN_HIGH_FRAME_TYPE].Backlog || !RoundTripContexts[TSN_LOW_FRAME_TYPE].Backlog ||
        !RoundTripContexts[RTC_FRAME_TYPE].Backlog || !RoundTripContexts[RTA_FRAME_TYPE].Backlog ||
        !RoundTripContexts[DCP_FRAME_TYPE].Backlog || !RoundTripContexts[LLDP_FRAME_TYPE].Backlog ||
        !RoundTripContexts[UDP_HIGH_FRAME_TYPE].Backlog || !RoundTripContexts[UDP_LOW_FRAME_TYPE].Backlog ||
        !RoundTripContexts[GENERICL2_FRAME_TYPE].Backlog)
        return -ENOMEM;

    GlobalStatistics[TSN_HIGH_FRAME_TYPE].RoundTripMin = UINT64_MAX;
    GlobalStatistics[TSN_LOW_FRAME_TYPE].RoundTripMin = UINT64_MAX;
    GlobalStatistics[RTC_FRAME_TYPE].RoundTripMin = UINT64_MAX;
    GlobalStatistics[RTA_FRAME_TYPE].RoundTripMin = UINT64_MAX;
    GlobalStatistics[DCP_FRAME_TYPE].RoundTripMin = UINT64_MAX;
    GlobalStatistics[LLDP_FRAME_TYPE].RoundTripMin = UINT64_MAX;
    GlobalStatistics[UDP_HIGH_FRAME_TYPE].RoundTripMin = UINT64_MAX;
    GlobalStatistics[UDP_LOW_FRAME_TYPE].RoundTripMin = UINT64_MAX;
    GlobalStatistics[GENERICL2_FRAME_TYPE].RoundTripMin = UINT64_MAX;

    if (appConfig.DebugStopTraceOnRtt)
    {
        FileTracingOn = fopen("/sys/kernel/debug/tracing/tracing_on", "w");
        if (!FileTracingOn)
            return -errno;
        FileTraceMarker = fopen("/sys/kernel/debug/tracing/trace_marker", "w");
        if (!FileTraceMarker)
        {
            fclose(FileTracingOn);
            return -errno;
        }
    }

    /*
     * The expected round trip limit for RT traffic classes is below < 2 * cycle time. Stored in us.
     */
    RttExpectedRTLimit = appConfig.ApplicationBaseCycleTimeNS * 2;
    RttExpectedRTLimit /= 1000;

    LogRtt = logRtt;

    return 0;
}

void StatFree(void)
{
    free(RoundTripContexts[TSN_HIGH_FRAME_TYPE].Backlog);
    free(RoundTripContexts[TSN_LOW_FRAME_TYPE].Backlog);
    free(RoundTripContexts[RTC_FRAME_TYPE].Backlog);
    free(RoundTripContexts[RTA_FRAME_TYPE].Backlog);
    free(RoundTripContexts[DCP_FRAME_TYPE].Backlog);
    free(RoundTripContexts[LLDP_FRAME_TYPE].Backlog);
    free(RoundTripContexts[UDP_HIGH_FRAME_TYPE].Backlog);
    free(RoundTripContexts[UDP_LOW_FRAME_TYPE].Backlog);

    if (appConfig.DebugStopTraceOnRtt)
    {
        fclose(FileTracingOn);
        fclose(FileTraceMarker);
    }
}

void StatFrameSent(enum StatFrameType frameType, uint64_t cycleNumber)
{
    struct RoundTripContext *rtt = &RoundTripContexts[frameType];
    struct Statistics *stat = &GlobalStatistics[frameType];
    struct timespec txTime = {};

    LogMessage(LOG_LEVEL_DEBUG, "%s: frame[%" PRIu64 "] sent\n", StatFrameTypeToString(frameType), cycleNumber);

    if (LogRtt)
    {
        /* Record Tx timestamp in */
        clock_gettime(appConfig.ApplicationClockId, &txTime);
        rtt->Backlog[cycleNumber % rtt->BacklogLen] = TsToNs(&txTime);
    }

    /* Increment stats */
    stat->FramesSent++;
}

void StatFrameReceived(enum StatFrameType frameType, uint64_t cycleNumber)
{
    struct RoundTripContext *rtt = &RoundTripContexts[frameType];
    struct Statistics *stat = &GlobalStatistics[frameType];
    struct timespec rxTime = {};
    uint64_t rtTime;

    LogMessage(LOG_LEVEL_DEBUG, "%s: frame[%" PRIu64 "] received\n", StatFrameTypeToString(frameType), cycleNumber);

    /* Record Rx timestamp in us */
    if (LogRtt)
    {
        clock_gettime(appConfig.ApplicationClockId, &rxTime);
        rtTime = TsToNs(&rxTime) - rtt->Backlog[cycleNumber % rtt->BacklogLen];
        rtTime /= 1000;

        if (rtTime < stat->RoundTripMin)
            stat->RoundTripMin = rtTime;
        if (rtTime > stat->RoundTripMax)
            stat->RoundTripMax = rtTime;
        if (StatFrameTypeIsRealTime(frameType) && rtTime > RttExpectedRTLimit)
            stat->RoundTripOutliers++;
        stat->RoundTripCount++;
        stat->RoundTripSum += rtTime;
        stat->RoundTripAvg = stat->RoundTripSum / (double)stat->RoundTripCount;

        /* Stop tracing after certain amount of time */
        if (appConfig.DebugStopTraceOnRtt && StatFrameTypeIsRealTime(frameType) &&
            rtTime > (appConfig.DebugStopTraceRttLimitNS / 1000))
        {
            fprintf(FileTraceMarker,
                    "Round-Trip Limit hit: %" PRIu64 " [us] -- Type: %d -- Cycle Counter: %" PRIu64 "\n", rtTime,
                    frameType, cycleNumber);
            fprintf(FileTracingOn, "0\n");
            fprintf(stderr, "Round-Trip Limit hit: %" PRIu64 " [us] -- Type: %d -- Cycle Counter: %" PRIu64 "\n",
                    rtTime, frameType, cycleNumber);
            fclose(FileTracingOn);
            fclose(FileTraceMarker);
            exit(EXIT_SUCCESS);
        }
    }

    /* Increment stats */
    stat->FramesReceived++;
}
