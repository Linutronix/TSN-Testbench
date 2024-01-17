/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _TX_TIME_H_
#define _TX_TIME_H_

#include <stddef.h>
#include <stdint.h>

uint64_t TxTimeGetFrameDuration(uint32_t linkSpeed, size_t frameLength);

uint64_t TxTimeGetFrameTxTime(uint64_t wakeupTime, uint64_t sequenceCounter, uint64_t duration,
                              size_t numFramesPerCycle, uint64_t txTimeOffset, const char *trafficClass);

#endif /* _TX_TIME_H_ */
