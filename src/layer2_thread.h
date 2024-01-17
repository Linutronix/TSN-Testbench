/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _LAYER2_THREAD_H_
#define _LAYER2_THREAD_H_

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include <linux/if_ether.h>

#include "thread.h"
#include "xdp.h"

#define GENL2_TX_FRAME_LENGTH XDP_FRAME_SIZE

struct ThreadContext *GenericL2ThreadsCreate(void);
void GenericL2ThreadsStop(struct ThreadContext *threadContext);
void GenericL2ThreadsFree(struct ThreadContext *threadContext);
void GenericL2ThreadsWaitForFinish(struct ThreadContext *threadContext);

#endif /* _LAYER2_THREAD_H_ */
