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

int rtc_threads_create(struct thread_context *thread_context);
void rtc_threads_stop(struct thread_context *thread_context);
void rtc_threads_free(struct thread_context *thread_context);
void rtc_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _RTC_THREAD_H_ */
