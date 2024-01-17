/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020,2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _LLDP_THREAD_H_
#define _LLDP_THREAD_H_

#include <pthread.h>

#include "thread.h"

#define LLDP_TX_FRAME_LENGTH (4096)

int LldpThreadsCreate(struct ThreadContext *threadContext);
void LldpThreadsStop(struct ThreadContext *threadContext);
void LldpThreadsFree(struct ThreadContext *threadContext);
void LldpThreadsWaitForFinish(struct ThreadContext *threadContext);

#endif /* _LLDP_THREAD_H_ */
