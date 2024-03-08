/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "ring_buffer.h"

/* 1 MiB per traffic class */
#define LOG_BUFFER_SIZE (8 * 1024 * 1024)

enum log_level {
	LOG_LEVEL_ERROR = 1,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_INFO,
	LOG_LEVEL_DEBUG
};

struct log_thread_context {
	pthread_t log_task_id;
	struct ring_buffer *log_ring_buffer;
	unsigned char *log_data;
	volatile int stop;
	FILE *file_handle;
};

struct log_thread_context *log_thread_create(void);
void log_thread_stop(struct log_thread_context *thread_context);
void log_thread_free(struct log_thread_context *thread_context);
void log_thread_wait_for_finish(struct log_thread_context *thread_context);

int log_init(void);
void log_message(enum log_level level, const char *format, ...)
	__attribute__((__format__(printf, 2, 3)));
void log_free(void);

#endif /* _LOG_H_ */
