/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _RTA_THREAD_H_
#define _RTA_THREAD_H_

#include <pthread.h>
#include <stdint.h>

#include "thread.h"
#include "xdp.h"

#define RTA_TX_FRAME_LENGTH XDP_FRAME_SIZE

int RtaThreadsCreate(struct ThreadContext *threadContext);
void RtaThreadsStop(struct ThreadContext *threadContext);
void RtaThreadsFree(struct ThreadContext *threadContext);
void RtaThreadsWaitForFinish(struct ThreadContext *threadContext);

#endif /* _RTA_THREAD_H_ */
