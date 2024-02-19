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
#include "logviamqtt.h"
#include "stat.h"
#include "utils.h"

struct Statistics GlobalStatistics[NUM_FRAME_TYPES];
struct Statistics GlobalStatisticsPerPeriod[NUM_FRAME_TYPES];
struct Statistics GlobalStatisticsPerPeriodPrep[NUM_FRAME_TYPES];
struct RoundTripContext RoundTripContexts[NUM_FRAME_TYPES];
static uint64_t RttExpectedRTLimit;
static bool LogRtt;
static FILE *FileTracingOn;
static FILE *FileTraceMarker;

static const char *StatFrameTypeNames[NUM_FRAME_TYPES] = {"TsnHigh", "TsnLow",  "Rtc",    "Rta",      "Dcp",
                                                          "Lldp",    "UdpHigh", "UdpLow", "GenericL2"};

inline const char *StatFrameTypeToString(enum StatFrameType frameType)
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
    bool allocationError = false;

    RoundTripContexts[TSN_HIGH_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.TsnHighNumFramesPerCycle;
    RoundTripContexts[TSN_LOW_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.TsnLowNumFramesPerCycle;
    RoundTripContexts[RTC_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.RtcNumFramesPerCycle;
    RoundTripContexts[RTA_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.RtaNumFramesPerCycle;
    RoundTripContexts[DCP_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.DcpNumFramesPerCycle;
    RoundTripContexts[LLDP_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.LldpNumFramesPerCycle;
    RoundTripContexts[UDP_HIGH_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.UdpHighNumFramesPerCycle;
    RoundTripContexts[UDP_LOW_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.UdpLowNumFramesPerCycle;
    RoundTripContexts[GENERICL2_FRAME_TYPE].BacklogLen = STAT_MAX_BACKLOG * appConfig.GenericL2NumFramesPerCycle;

    for (int i = 0; i < NUM_FRAME_TYPES; i++)
    {
        struct RoundTripContext *currentContext = &RoundTripContexts[i];

        currentContext->Backlog = calloc(currentContext->BacklogLen, sizeof(int64_t));
        allocationError |= !currentContext->Backlog;
    }

    if (allocationError)
        return -ENOMEM;

    for (int i = 0; i < NUM_FRAME_TYPES; i++)
    {
        struct Statistics *currentStats = &GlobalStatistics[i];

        currentStats->RoundTripMin = UINT64_MAX;
        currentStats->RoundTripMax = 0;
        currentStats = &GlobalStatisticsPerPeriod[i];
        currentStats->RoundTripMin = UINT64_MAX;
        currentStats->RoundTripMax = 0;
    }

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

    for (int i = 0; i < NUM_FRAME_TYPES; i++)
        free(RoundTripContexts[i].Backlog);

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

static inline void StatUpdateMinMax(uint64_t newValue, uint64_t *min, uint64_t *max)
{
    *max = (newValue > *max) ? newValue : *max;
    *min = (newValue < *min) ? newValue : *min;
}

static void StatsResetStats(struct Statistics *stats)
{
    memset(stats, 0, sizeof(struct Statistics));
    stats->RoundTripMin = UINT64_MAX;
}

static void StatFrameReceivedPerPeriod(enum StatFrameType frameType, uint64_t currTime, uint64_t rtTime,
                                       bool outOfOrder, bool payloadMismatch, bool frameIdMismatch)
{
    struct Statistics *statPerPeriodPre = &GlobalStatisticsPerPeriodPrep[frameType];
    uint64_t elapsedT;

    if (statPerPeriodPre->FirstTimeStamp == 0)
        statPerPeriodPre->FirstTimeStamp = currTime;

    /* Test if the amount of time specified in the config is arrived.
     * if true this will be the last point to be taken into stats per period */
    elapsedT = currTime - statPerPeriodPre->FirstTimeStamp;
    if (elapsedT >= appConfig.StatsCollectionIntervalNS)
    {
        statPerPeriodPre->ready = true;
        statPerPeriodPre->LastTimeStamp = currTime;
    }

    if (StatFrameTypeIsRealTime(frameType) && rtTime > RttExpectedRTLimit)
        statPerPeriodPre->RoundTripOutliers++;

    StatUpdateMinMax(rtTime, &statPerPeriodPre->RoundTripMin, &statPerPeriodPre->RoundTripMax);

    statPerPeriodPre->RoundTripCount++;
    statPerPeriodPre->RoundTripSum += rtTime;
    statPerPeriodPre->RoundTripAvg = statPerPeriodPre->RoundTripSum / (double)statPerPeriodPre->RoundTripCount;

    statPerPeriodPre->FramesReceived++;
    statPerPeriodPre->OutOfOrderErrors += outOfOrder;
    statPerPeriodPre->PayloadErrors += payloadMismatch;
    statPerPeriodPre->FrameIdErrors += frameIdMismatch;

    /* Final bits can be used in the logger reseting copying actual values and
     * reseting the preparation */
    if (statPerPeriodPre->ready)
    {
        LogViaMQTTStats(frameType, &GlobalStatisticsPerPeriodPrep[frameType]);
        StatsResetStats(&GlobalStatisticsPerPeriodPrep[frameType]);
    }
}

void StatFrameReceived(enum StatFrameType frameType, uint64_t cycleNumber, bool outOfOrder, bool payloadMismatch,
                       bool frameIdMismatch)
{
    struct RoundTripContext *rtt = &RoundTripContexts[frameType];
    struct Statistics *stat = &GlobalStatistics[frameType];
    struct timespec rxTime = {};
    uint64_t rtTime;
    uint64_t currTime;

    LogMessage(LOG_LEVEL_DEBUG, "%s: frame[%" PRIu64 "] received\n", StatFrameTypeToString(frameType), cycleNumber);

    /* Record Rx timestamp in us */
    if (LogRtt)
    {
        clock_gettime(appConfig.ApplicationClockId, &rxTime);
        currTime = TsToNs(&rxTime);
        rtTime = currTime - rtt->Backlog[cycleNumber % rtt->BacklogLen];
        rtTime /= 1000;

        StatFrameReceivedPerPeriod(frameType, currTime, rtTime, outOfOrder, payloadMismatch, frameIdMismatch);

        StatUpdateMinMax(rtTime, &stat->RoundTripMin, &stat->RoundTripMax);
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
    stat->OutOfOrderErrors += outOfOrder;
    stat->PayloadErrors += payloadMismatch;
    stat->FrameIdErrors += frameIdMismatch;
}
