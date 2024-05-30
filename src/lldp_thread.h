/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _LLDP_THREAD_H_
#define _LLDP_THREAD_H_

#include <pthread.h>

#include "thread.h"

int lldp_threads_create(struct thread_context *thread_context);
void lldp_threads_free(struct thread_context *thread_context);
void lldp_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _LLDP_THREAD_H_ */
