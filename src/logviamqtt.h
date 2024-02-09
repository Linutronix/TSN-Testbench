// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024 Intel Corporation.
 * Author Walfred Tedeschi <walfred.tedeschi@intel.com>
 */

#ifndef _LOGVIAMQTT_H_
#define _LOGVIAMQTT_H_

struct Statistics;
enum StatFrameType;

struct LogViaMQTTThreadContext
{
    pthread_t MQTTLogTaskId;
    struct mosquitto *mosq;
    struct RingBuffer *MQTTLogRingBuffer;
    unsigned char *MQTTLogData;
    volatile int Stop;
};

struct LogViaMQTTThreadContext *LogViaMQTTThreadCreate();
void LogViaMQTTStats(enum StatFrameType frameType, struct Statistics *stats);
void LogViaMQTTThreadStop(struct LogViaMQTTThreadContext *threadContext);
void LogViaMQTTThreadFree(struct LogViaMQTTThreadContext *threadContext);
void LogViaMQTTThreadWaitForFinish(struct LogViaMQTTThreadContext *threadContext);

void LogViaMQTTFree(void);

#endif /*LOGVIAMQTT*/
