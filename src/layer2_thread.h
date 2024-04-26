/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022-2024 Linutronix GmbH
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

static inline unsigned char *g2_idx(unsigned char *frame_data, int idx)
{
	return frame_data + idx * GENL2_TX_FRAME_LENGTH;
}

struct thread_context *generic_l2_threads_create(void);
void generic_l2_threads_stop(struct thread_context *thread_context);
void generic_l2_threads_free(struct thread_context *thread_context);
void generic_l2_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _LAYER2_THREAD_H_ */
