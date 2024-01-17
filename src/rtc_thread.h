/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _RTC_THREAD_H_
#define _RTC_THREAD_H_

#include <pthread.h>
#include <stdint.h>

#include "thread.h"
#include "xdp.h"

#define RTC_TX_FRAME_LENGTH XDP_FRAME_SIZE

int RtcThreadsCreate(struct ThreadContext *threadContext);
void RtcThreadsStop(struct ThreadContext *threadContext);
void RtcThreadsFree(struct ThreadContext *threadContext);
void RtcThreadsWaitForFinish(struct ThreadContext *threadContext);

#endif /* _RTC_THREAD_H_ */
