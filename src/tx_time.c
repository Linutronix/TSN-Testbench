// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include "tx_time.h"

#include "config.h"
#include "log.h"
#include "utils.h"

uint64_t TxTimeGetFrameDuration(uint32_t linkSpeed, size_t frameLength)
{
    uint64_t duration_ns;

    /* ((frameLength * 8) / (linkSpeed * 1000000ULL)) * 1000000000ULL */
    duration_ns = (frameLength * 8 * 1000) / linkSpeed;

    return duration_ns;
}

uint64_t TxTimeGetFrameTxTime(uint64_t wakeupTime, uint64_t sequenceCounter, uint64_t duration,
                              size_t numFramesPerCycle, uint64_t txTimeOffset, const char *trafficClass)
{
    const uint64_t txThreadOffset = appConfig.ApplicationTxBaseOffsetNS;
    const uint64_t cycleTime = appConfig.ApplicationBaseCycleTimeNS;
    uint64_t txTime, baseTime, nowNs;
    struct timespec now;

    /*
     * Calculate frame transmission time for next cycle. txTimeOffset is
     * used to specify the offset within cycle, which has to be aligned with
     * configured Qbv schedule.
     *
     *   BaseTime + TxOffset +
     *   (sequenceCounter % numFramesPerCycle) * duration
     *
     *   |---------------------------|---------------------------|
     *   ^BaseTime   ^TxThreadoffset    ^^^^^^
     *
     * All calculations are performed in nanoseconds.
     */

    baseTime = wakeupTime - txThreadOffset + cycleTime;

    txTime = baseTime + txTimeOffset + (sequenceCounter % numFramesPerCycle) * duration;

    /*
     * TxTime has to be in the future. If not the frame will be dropped by
     * ETF Qdisc. This may happen due to delays, preemption and so
     * on. Inform the user accordingly.
     */
    clock_gettime(appConfig.ApplicationClockId, &now);
    nowNs = TsToNs(&now);

    if (txTime <= nowNs)
        LogMessage(LOG_LEVEL_ERROR, "%sTx: TxTime not in future!\n", trafficClass);

    return txTime;
}
