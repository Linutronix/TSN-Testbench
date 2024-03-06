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

int lldp_threads_create(struct thread_context *thread_context);
void lldp_threads_stop(struct thread_context *thread_context);
void lldp_threads_free(struct thread_context *thread_context);
void lldp_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _LLDP_THREAD_H_ */
