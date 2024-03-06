// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024 Intel Corporation.
 * Author Walfred Tedeschi <walfred.tedeschi@intel.com>
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app_config.h"
#ifdef WITH_MQTT
#include <mosquitto.h>
#endif

#include "config.h"
#include "logviamqtt.h"
#include "ring_buffer.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

#define LOGVIAMQTT_BUFFER_SIZE (8 * 1024)

#ifndef WITH_MQTT
struct LogViaMQTTThreadContext *LogViaMQTTThreadCreate()
{
    return NULL;
}

void LogViaMQTTThreadWaitForFinish(struct LogViaMQTTThreadContext *threadContext)
{
}

void LogViaMQTTStats(enum StatFrameType frameType, struct Statistics *stats)
{
}

void LogViaMQTTFree()
{
}

#else

static struct RingBuffer *LogViaMQTTGlobalLogRingBuffer;

struct LogStatistics
{
    enum StatFrameType FrameType;
    uint64_t TimeStamp;
    uint64_t FramesSent;
    uint64_t FramesReceived;
    uint64_t OutOfOrderErrors;
    uint64_t FrameIdErrors;
    uint64_t PayloadErrors;
    uint64_t RoundTripMin;
    uint64_t RoundTripMax;
    uint64_t RoundTripOutliers;
    double RoundTripAvg;
};

int LogViaMQTTInit()
{
    LogViaMQTTGlobalLogRingBuffer = RingBufferAllocate(LOGVIAMQTT_BUFFER_SIZE);
    if (!LogViaMQTTGlobalLogRingBuffer)
        return -ENOMEM;

    return 0;
}

void LogViaMQTTStats(enum StatFrameType frameType, struct Statistics *stats)
{
    struct LogStatistics internal;

    internal.FrameType = frameType;
    internal.TimeStamp = stats->LastTimeStamp;
    internal.FramesSent = stats->FramesSent;
    internal.FramesReceived = stats->FramesReceived;
    internal.OutOfOrderErrors = stats->OutOfOrderErrors;
    internal.FrameIdErrors = stats->FrameIdErrors;
    internal.PayloadErrors = stats->PayloadErrors;
    internal.RoundTripMin = stats->RoundTripMin;
    internal.RoundTripMax = stats->RoundTripMax;
    internal.RoundTripOutliers = stats->RoundTripOutliers;
    internal.RoundTripAvg = stats->RoundTripAvg;

    RingBufferAdd(LogViaMQTTGlobalLogRingBuffer, (const unsigned char *)&internal, sizeof(struct LogStatistics));
}

static void LogViaMQTTAddTrafficClass(struct mosquitto *mosq, const char *MQTTBaseTopicName, struct LogStatistics *stat)
{
    char statMessage[1024] = {}, *p;
    size_t statMessageLength;
    int written, resultPub;
    uint64_t timeNs;

    statMessageLength = sizeof(statMessage) - 1;
    p = statMessage;

    timeNs = stat->TimeStamp;
    written = snprintf(p, statMessageLength,
                       "{\"%s\" :\n"
                       "\t{\"Timestamp\" : %" PRIu64 ",\n"
                       "\t \"MeasurementName\" : \"%s\"",
                       "reference", timeNs, MQTTBaseTopicName);

    p += written;
    statMessageLength -= written;

    written = snprintf(p, statMessageLength,
                       ",\n\t\t\"%s\" : \n\t\t{\n"
                       "\t\t\t\"TCName\" : \"%s\",\n"
                       "\t\t\t\"FramesSent\" : %" PRIu64 ",\n"
                       "\t\t\t\"FramesReceived\" : %" PRIu64 ",\n"
                       "\t\t\t\"RoundTripTime\" : %" PRIu64 ",\n"
                       "\t\t\t\"RoundTripMax\" : %" PRIu64 ",\n"
                       "\t\t\t\"RoundTripAv\" : %lf,\n"
                       "\t\t\t\"OutofOrderErrors\" : %" PRIu64 ",\n"
                       "\t\t\t\"FrameIdErrors\" : %" PRIu64 ",\n"
                       "\t\t\t\"PayloadErrors\" : %" PRIu64 ",\n"
                       "\t\t\t\"RoundTripOutliers\" : %" PRIu64 "\n\t\t}",
                       "stats", StatFrameTypeToString(stat->FrameType), stat->FramesSent, stat->FramesReceived,
                       stat->RoundTripMin, stat->RoundTripMax, stat->RoundTripAvg, stat->OutOfOrderErrors,
                       stat->FrameIdErrors, stat->PayloadErrors, stat->RoundTripOutliers);

    p += written;
    statMessageLength -= written;

    written = snprintf(p, statMessageLength, "\t\t\n}\t\n}\n");

    p += written;
    statMessageLength -= written;

    resultPub = mosquitto_publish(mosq, NULL, "testbench", strlen(statMessage), statMessage, 2, false);
    if (resultPub != MOSQ_ERR_SUCCESS)
        fprintf(stderr, "Error publishing: %s\n", mosquitto_strerror(resultPub));
}

static void LogViaMQTTOnConnect(struct mosquitto *mosq, void *obj, int reason_code)
{
    if (reason_code != 0)
        mosquitto_disconnect(mosq);
}

static void *LogViaMQTTThreadRoutine(void *data)
{
    uint64_t periodNS = appConfig.LogViaMQTTThreadPeriodNS;
    struct LogViaMQTTThreadContext *mqttContext = data;
    struct LogStatistics stats[10 * NUM_FRAME_TYPES];
    int ret, connectStatus;
    struct timespec time;
    size_t logDataLen;

    mosquitto_lib_init();

    mqttContext->mosq = mosquitto_new(NULL, true, NULL);
    if (mqttContext->mosq == NULL)
    {
        fprintf(stderr, "MQTTLog Error: Out of memory.\n");
        goto err_mqtt_outof_memory;
    }

    connectStatus = mosquitto_connect(mqttContext->mosq, appConfig.LogViaMQTTBrokerIP, appConfig.LogViaMQTTBrokerPort,
                                      appConfig.LogViaMQTTKeepAliveSecs);
    if (connectStatus != MOSQ_ERR_SUCCESS)
    {
        fprintf(stderr, "MQTTLog Error by connect: %s\n", mosquitto_strerror(connectStatus));
        goto err_mqtt_connect;
    }

    mosquitto_connect_callback_set(mqttContext->mosq, LogViaMQTTOnConnect);

    ret = mosquitto_loop_start(mqttContext->mosq);
    if (ret != MOSQ_ERR_SUCCESS)
    {
        fprintf(stderr, "Log Via MQTT Error: %s\n", mosquitto_strerror(ret));
        goto err_mqtt_start;
    }

    /*
     * Send the statistics periodically to the MQTT broker.  This thread can run with low priority to not influence to
     * Application Tasks that much.
     */
    ret = clock_gettime(appConfig.ApplicationClockId, &time);
    if (ret)
    {
        fprintf(stderr, "Log Via MQTT: clock_gettime() failed: %s!", strerror(errno));
        goto err_time;
    }

    while (!mqttContext->Stop)
    {
        struct LogStatistics *currStats;
        int nofReadElements;

        IncrementPeriod(&time, periodNS);
        ret = clock_nanosleep(appConfig.ApplicationClockId, TIMER_ABSTIME, &time, NULL);
        if (ret)
        {
            PthreadError(ret, "clock_nanosleep() failed");
            goto err_time;
        }

        RingBufferFetch(mqttContext->MQTTLogRingBuffer, (unsigned char *)&stats, sizeof(stats), &logDataLen);
        nofReadElements = logDataLen / sizeof(struct LogStatistics);

        currStats = (struct LogStatistics *)stats;
        for (int i = 0; i < nofReadElements; i++)
            LogViaMQTTAddTrafficClass(mqttContext->mosq, appConfig.LogViaMQTTMeasurementName, &currStats[i]);
    }

    return NULL;

err_mqtt_outof_memory:
err_mqtt_connect:
err_mqtt_start:
err_time:
    if (mqttContext->mosq)
        mosquitto_destroy(mqttContext->mosq);
    mosquitto_lib_cleanup();
    return NULL;
}

struct LogViaMQTTThreadContext *LogViaMQTTThreadCreate(void)
{
    struct LogViaMQTTThreadContext *mqttContext;
    int initVal, ret = 0;

    if (!appConfig.LogViaMQTT)
        return NULL;

    mqttContext = malloc(sizeof(*mqttContext));
    if (!mqttContext)
        return NULL;

    memset(mqttContext, '\0', sizeof(*mqttContext));

    initVal = LogViaMQTTInit();
    if (initVal != 0)
        goto err_thread;

    mqttContext->MQTTLogRingBuffer = LogViaMQTTGlobalLogRingBuffer;

    ret = CreateRtThread(&mqttContext->MQTTLogTaskId, "LoggerGraph", appConfig.LogViaMQTTThreadPriority,
                         appConfig.LogViaMQTTThreadCpu, LogViaMQTTThreadRoutine, mqttContext);

    if (ret)
        goto err_thread;

    return mqttContext;

err_thread:
    free(mqttContext);
    return NULL;
}

void LogViaMQTTThreadFree(struct LogViaMQTTThreadContext *threadContext)
{
    if (!threadContext)
        return;

    if (appConfig.LogViaMQTT)
    {
        if (threadContext->mosq)
            mosquitto_destroy(threadContext->mosq);
        mosquitto_lib_cleanup();
    }

    free(threadContext);
}

void LogViaMQTTThreadStop(struct LogViaMQTTThreadContext *threadContext)
{
    if (!threadContext)
        return;

    threadContext->Stop = 1;
    pthread_join(threadContext->MQTTLogTaskId, NULL);
}

void LogViaMQTTFree()
{
    RingBufferFree(LogViaMQTTGlobalLogRingBuffer);
}

void LogViaMQTTThreadWaitForFinish(struct LogViaMQTTThreadContext *threadContext)
{
    if (!threadContext)
        return;

    pthread_join(threadContext->MQTTLogTaskId, NULL);
}
#endif
