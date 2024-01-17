/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _DCP_THREAD_H_
#define _DCP_THREAD_H_

#include <pthread.h>
#include <stdint.h>

#include <linux/if_ether.h>

#include "thread.h"

#define DCP_TX_FRAME_LENGTH (4096)

int DcpThreadsCreate(struct ThreadContext *threadContext);
void DcpThreadsStop(struct ThreadContext *threadContext);
void DcpThreadsFree(struct ThreadContext *threadContext);
void DcpThreadsWaitForFinish(struct ThreadContext *threadContext);

#endif /* _DCP_THREAD_H_ */
