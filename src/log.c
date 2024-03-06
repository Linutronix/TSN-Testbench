// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "log.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

static struct RingBuffer *GlobalLogRingBuffer;
static enum LogLevel CurrentLogLevel;
static FILE *FileTracingOn;

int LogInit(void)
{
	GlobalLogRingBuffer = RingBufferAllocate(LOG_BUFFER_SIZE);

	if (!GlobalLogRingBuffer)
		return -ENOMEM;

	/* Default */
	CurrentLogLevel = LOG_LEVEL_DEBUG;

	if (!strcmp(appConfig.LogLevel, "Debug"))
		CurrentLogLevel = LOG_LEVEL_DEBUG;
	if (!strcmp(appConfig.LogLevel, "Info"))
		CurrentLogLevel = LOG_LEVEL_INFO;
	if (!strcmp(appConfig.LogLevel, "Warning"))
		CurrentLogLevel = LOG_LEVEL_WARNING;
	if (!strcmp(appConfig.LogLevel, "Error"))
		CurrentLogLevel = LOG_LEVEL_ERROR;

	if (appConfig.DebugStopTraceOnError) {
		FileTracingOn = fopen("/sys/kernel/debug/tracing/tracing_on", "w");
		if (!FileTracingOn)
			return -errno;
	}

	return 0;
}

void LogFree(void)
{
	RingBufferFree(GlobalLogRingBuffer);

	if (appConfig.DebugStopTraceOnError)
		fclose(FileTracingOn);
}

static const char *LogLevelToString(enum LogLevel level)
{
	if (level == LOG_LEVEL_DEBUG)
		return "DEBUG";
	if (level == LOG_LEVEL_INFO)
		return "INFO";
	if (level == LOG_LEVEL_WARNING)
		return "WARNING";
	if (level == LOG_LEVEL_ERROR)
		return "ERROR";

	return NULL;
}

void LogMessage(enum LogLevel level, const char *format, ...)
{
	unsigned char buffer[4096];
	int written, len, ret;
	struct timespec time;
	va_list args;
	char *p;

	/*
	 * Stop trace on error if desired.
	 */
	if (level == LOG_LEVEL_ERROR && appConfig.DebugStopTraceOnError)
		fprintf(FileTracingOn, "0\n");

	/*
	 * Log message only if log level fulfilled.
	 */
	if (level > CurrentLogLevel)
		return;

	/*
	 * Log each message with time stamps.
	 */

	ret = clock_gettime(appConfig.ApplicationClockId, &time);
	if (ret)
		memset(&time, '\0', sizeof(time));

	len = sizeof(buffer) - 1;
	p = (char *)buffer;

	written = snprintf(p, len, "[%8ld.%9ld]: [%s]: ", time.tv_sec, time.tv_nsec,
			   LogLevelToString(level));
	p += written;
	len -= written;

	va_start(args, format);
	written += vsnprintf(p, len, format, args);
	va_end(args);

	RingBufferAdd(GlobalLogRingBuffer, buffer, written);
}

static void LogAddTrafficClass(const char *name, enum StatFrameType frameType, char **buffer,
			       size_t *length)
{
	const struct Statistics *stat = &GlobalStatistics[frameType];
	int written;

	written = snprintf(*buffer, *length,
			   "%sSent=%" PRIu64 " | %sReceived=%" PRIu64 " | %sRttMin=%" PRIu64
			   " [us] | %sRttMax=%" PRIu64 " [us] | %sRttAvg=%lf [us] | ",
			   name, stat->FramesSent, name, stat->FramesReceived, name,
			   stat->RoundTripMin, name, stat->RoundTripMax, name, stat->RoundTripAvg);

	*buffer += written;
	*length -= written;

	if (StatFrameTypeIsRealTime(frameType)) {
		written = snprintf(*buffer, *length, "%sRttOutliers=%" PRIu64 " | ", name,
				   stat->RoundTripOutliers);
		*buffer += written;
		*length -= written;
	}
}

static void *LogThreadRoutine(void *data)
{
	struct LogThreadContext *logContext = data;
	uint64_t period = appConfig.LogThreadPeriodNS;
	struct timespec time;
	int ret;

	/*
	 * Write the content of the LogBuffer periodically to disk.  This thread
	 * can run with low priority to not influence to Application Tasks that
	 * much.
	 */
	ret = clock_gettime(appConfig.ApplicationClockId, &time);
	if (ret) {
		fprintf(stderr, "Log: clock_gettime() failed: %s!", strerror(errno));
		return NULL;
	}

	while (!logContext->Stop) {
		size_t logDataLen, statMessageLength;
		char statMessage[4096] = {}, *p;

		/* Wait until next period */
		IncrementPeriod(&time, period);
		ret = clock_nanosleep(appConfig.ApplicationClockId, TIMER_ABSTIME, &time, NULL);
		if (ret) {
			PthreadError(ret, "clock_nanosleep() failed");
			return NULL;
		}

		/* Log statistics once per logging period. */
		p = statMessage;
		statMessageLength = sizeof(statMessage) - 1;

		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(TsnHigh))
			LogAddTrafficClass("TsnHigh", TSN_HIGH_FRAME_TYPE, &p, &statMessageLength);
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(TsnLow))
			LogAddTrafficClass("TsnLow", TSN_LOW_FRAME_TYPE, &p, &statMessageLength);
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Rtc))
			LogAddTrafficClass("Rtc", RTC_FRAME_TYPE, &p, &statMessageLength);
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Rta))
			LogAddTrafficClass("Rta", RTA_FRAME_TYPE, &p, &statMessageLength);
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Dcp))
			LogAddTrafficClass("Dcp", DCP_FRAME_TYPE, &p, &statMessageLength);
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Lldp))
			LogAddTrafficClass("Lldp", LLDP_FRAME_TYPE, &p, &statMessageLength);
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(UdpHigh))
			LogAddTrafficClass("UdpHigh", UDP_HIGH_FRAME_TYPE, &p, &statMessageLength);
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(UdpLow))
			LogAddTrafficClass("UdpLow", UDP_LOW_FRAME_TYPE, &p, &statMessageLength);
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(GenericL2))
			LogAddTrafficClass(appConfig.GenericL2Name, GENERICL2_FRAME_TYPE, &p,
					   &statMessageLength);

		LogMessage(LOG_LEVEL_INFO, "%s\n", statMessage);

		/* Fetch data */
		RingBufferFetch(logContext->LogRingBuffer, logContext->LogData, LOG_BUFFER_SIZE,
				&logDataLen);

		/* Write down to disk */
		if (logDataLen > 0) {
			fwrite(logContext->LogData, sizeof(char), logDataLen,
			       logContext->FileHandle);
			fflush(logContext->FileHandle);
		}
	}

	return NULL;
}

struct LogThreadContext *LogThreadCreate(void)
{
	struct LogThreadContext *logContext;
	int ret;

	logContext = malloc(sizeof(*logContext));
	if (!logContext)
		return NULL;

	memset(logContext, '\0', sizeof(*logContext));

	logContext->LogData = malloc(LOG_BUFFER_SIZE);
	if (!logContext->LogData)
		goto err_log_data;
	memset(logContext->LogData, '\0', LOG_BUFFER_SIZE);

	logContext->LogRingBuffer = GlobalLogRingBuffer;

	logContext->FileHandle = fopen(appConfig.LogFile, "w+");
	if (!logContext->FileHandle)
		goto err_fopen;

	ret = CreateRtThread(&logContext->LogTaskId, "Logger", appConfig.LogThreadPriority,
			     appConfig.LogThreadCpu, LogThreadRoutine, logContext);
	if (ret)
		goto err_thread;

	return logContext;

err_thread:
	fclose(logContext->FileHandle);
err_fopen:
	free(logContext->LogData);
err_log_data:
	free(logContext);

	return NULL;
}

void LogThreadStop(struct LogThreadContext *threadContext)
{
	if (!threadContext)
		return;

	threadContext->Stop = 1;
	pthread_join(threadContext->LogTaskId, NULL);
}

void LogThreadFree(struct LogThreadContext *threadContext)
{
	if (!threadContext)
		return;

	fclose(threadContext->FileHandle);
	free(threadContext);
}

void LogThreadWaitForFinish(struct LogThreadContext *threadContext)
{
	if (!threadContext)
		return;

	pthread_join(threadContext->LogTaskId, NULL);
}
