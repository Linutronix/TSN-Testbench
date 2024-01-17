/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020,2021 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "ring_buffer.h"

/* 4 MiB / core */
#define LOG_BUFFER_SIZE (32 * 1024 * 1024)

enum LogLevel
{
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
};

struct LogThreadContext
{
    pthread_t LogTaskId;
    struct RingBuffer *LogRingBuffer;
    unsigned char *LogData;
    volatile int Stop;
    FILE *FileHandle;
};

struct LogThreadContext *LogThreadCreate();
void LogThreadStop(struct LogThreadContext *threadContext);
void LogThreadFree(struct LogThreadContext *threadContext);
void LogThreadWaitForFinish(struct LogThreadContext *threadContext);

int LogInit(void);
void LogMessage(enum LogLevel level, const char *format, ...) __attribute__((__format__(printf, 2, 3)));
void LogFree(void);

#endif /* _LOG_H_ */
