// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_vlan.h>

#include "config.h"
#include "log.h"
#include "net.h"
#include "net_def.h"
#include "stat.h"
#include "thread.h"
#include "udp_thread.h"
#include "utils.h"

static void UdpInitializeFrame(const struct UdpThreadConfiguration *udpConfig,
			       unsigned char *frameData)
{
	struct ReferenceMetaData *meta;

	/*
	 * UdpFrame:
	 *   Cycle counter
	 *   Payload
	 *   Padding to maxFrame
	 */

	/* Payload: SequenceCounter + Data */
	meta = (struct ReferenceMetaData *)frameData;
	memset(meta, '\0', sizeof(*meta));
	memcpy(frameData + sizeof(*meta), udpConfig->UdpPayloadPattern,
	       udpConfig->UdpPayloadPatternLength);

	/* Padding: '\0' */
}

static void UdpSendFrame(const struct UdpThreadConfiguration *udpConfig,
			 const unsigned char *frameData, size_t frameLength,
			 size_t numFramesPerCycle, int socketFd,
			 const struct sockaddr_storage *destination)
{
	struct ReferenceMetaData *meta;
	uint64_t sequenceCounter;
	ssize_t ret = -1;

	/* Fetch meta data */
	meta = (struct ReferenceMetaData *)frameData;
	sequenceCounter = MetaDataToSequenceCounter(meta, numFramesPerCycle);

	/* Send it */
	switch (destination->ss_family) {
	case AF_INET:
		ret = sendto(socketFd, frameData, frameLength, 0, (struct sockaddr_in *)destination,
			     sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		ret = sendto(socketFd, frameData, frameLength, 0,
			     (struct sockaddr_in6 *)destination, sizeof(struct sockaddr_in6));
		break;
	}
	if (ret < 0) {
		LogMessage(LOG_LEVEL_ERROR, "Udp%sTx: send() for %" PRIu64 " failed: %s\n",
			   udpConfig->UdpSuffix, sequenceCounter, strerror(errno));
		return;
	}

	StatFrameSent(udpConfig->FrameType, sequenceCounter);
}

static void UdpGenAndSendFrame(const struct UdpThreadConfiguration *udpConfig,
			       unsigned char *frameData, size_t frameLength,
			       size_t numFramesPerCycle, int socketFd, uint64_t sequenceCounter,
			       const struct sockaddr_storage *destination)
{
	struct ReferenceMetaData *meta;
	ssize_t ret = -1;

	/* Adjust meta data */
	meta = (struct ReferenceMetaData *)frameData;
	SequenceCounterToMetaData(meta, sequenceCounter, numFramesPerCycle);

	/* Send it */
	switch (destination->ss_family) {
	case AF_INET:
		ret = sendto(socketFd, frameData, frameLength, 0, (struct sockaddr_in *)destination,
			     sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		ret = sendto(socketFd, frameData, frameLength, 0,
			     (struct sockaddr_in6 *)destination, sizeof(struct sockaddr_in6));
		break;
	default:
		ret = -EINVAL;
	}
	if (ret < 0) {
		LogMessage(LOG_LEVEL_ERROR, "Udp%sTx: send() for %" PRIu64 " failed: %s\n",
			   udpConfig->UdpSuffix, sequenceCounter, strerror(errno));
		return;
	}

	StatFrameSent(udpConfig->FrameType, sequenceCounter);
}

static void *UdpTxThreadRoutine(void *data)
{
	struct ThreadContext *threadContext = data;
	const struct UdpThreadConfiguration *udpConfig = threadContext->PrivateData;
	unsigned char receivedFrames[UDP_TX_FRAME_LENGTH * udpConfig->UdpNumFramesPerCycle];
	const bool mirrorEnabled = udpConfig->UdpRxMirrorEnabled;
	pthread_mutex_t *mutex = &threadContext->DataMutex;
	pthread_cond_t *cond = &threadContext->DataCondVar;
	uint64_t sequenceCounter = 0;
	unsigned char *frame;
	int socketFd;

	socketFd = threadContext->SocketFd;
	frame = threadContext->TxFrameData;

	UdpInitializeFrame(udpConfig, frame);

	while (!threadContext->Stop) {
		size_t numFrames, i;

		/*
		 * Wait until signalled. These UDP frames have to be sent after
		 * the LLDP frames. Therefore, the LLDP or UDP High TxThread
		 * signals this one here.
		 */
		pthread_mutex_lock(mutex);
		pthread_cond_wait(cond, mutex);
		numFrames = threadContext->NumFramesAvailable;
		threadContext->NumFramesAvailable = 0;
		pthread_mutex_unlock(mutex);

		/*
		 * Send UdpFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirrorEnabled) {
			/* Send UdpFrames */
			for (i = 0; i < numFrames; ++i)
				UdpGenAndSendFrame(udpConfig, frame, udpConfig->UdpFrameLength,
						   udpConfig->UdpNumFramesPerCycle, socketFd,
						   sequenceCounter++, &threadContext->Destination);
		} else {
			size_t len;

			RingBufferFetch(threadContext->MirrorBuffer, receivedFrames,
					sizeof(receivedFrames), &len);

			/* Len should be a multiple of frame size */
			for (i = 0; i < len / udpConfig->UdpFrameLength; ++i)
				UdpSendFrame(
					udpConfig, receivedFrames + i * udpConfig->UdpFrameLength,
					udpConfig->UdpFrameLength, udpConfig->UdpNumFramesPerCycle,
					socketFd, &threadContext->Destination);

			pthread_mutex_lock(&threadContext->DataMutex);
			threadContext->NumFramesAvailable = 0;
			pthread_mutex_unlock(&threadContext->DataMutex);
		}

		/* Signal next Tx thread */
		if (threadContext->Next) {
			pthread_mutex_lock(&threadContext->Next->DataMutex);
			if (threadContext->Next->NumFramesAvailable)
				pthread_cond_signal(&threadContext->Next->DataCondVar);
			pthread_mutex_unlock(&threadContext->Next->DataMutex);
		}
	}

	return NULL;
}

static void *UdpRxThreadRoutine(void *data)
{
	struct ThreadContext *threadContext = data;
	const struct UdpThreadConfiguration *udpConfig = threadContext->PrivateData;
	const unsigned char *expectedPattern = (const unsigned char *)udpConfig->UdpPayloadPattern;
	const size_t expectedPatternLength = udpConfig->UdpPayloadPatternLength;
	const size_t numFramesPerCycle = udpConfig->UdpNumFramesPerCycle;
	const bool mirrorEnabled = udpConfig->UdpRxMirrorEnabled;
	const bool ignoreRxErrors = udpConfig->UdpIgnoreRxErrors;
	const ssize_t frameLength = udpConfig->UdpFrameLength;
	unsigned char frame[UDP_TX_FRAME_LENGTH];
	uint64_t sequenceCounter = 0;
	int socketFd;

	socketFd = threadContext->SocketFd;

	while (!threadContext->Stop) {
		bool outOfOrder, payloadMismatch, frameIdMismatch;
		struct ReferenceMetaData *meta;
		uint64_t rxSequenceCounter;
		ssize_t len;

		/* Wait for UDP frame */
		len = recv(socketFd, frame, sizeof(frame), 0);
		if (len < 0) {
			LogMessage(LOG_LEVEL_ERROR, "Udp%sRx: recv() failed: %s\n",
				   udpConfig->UdpSuffix, strerror(errno));
			return NULL;
		}
		if (len == 0)
			return NULL;

		if (len != frameLength) {
			LogMessage(LOG_LEVEL_WARNING,
				   "Udp%sRx: Frame with wrong length received!\n",
				   udpConfig->UdpSuffix);
			continue;
		}

		/*
		 * Check cycle counter and payload. The ether type is checked by
		 * the attached BPF filter.
		 */
		meta = (struct ReferenceMetaData *)frame;
		rxSequenceCounter = MetaDataToSequenceCounter(meta, numFramesPerCycle);

		outOfOrder = sequenceCounter != rxSequenceCounter;
		payloadMismatch = memcmp(frame + sizeof(struct ReferenceMetaData), expectedPattern,
					 expectedPatternLength);
		frameIdMismatch = false;

		StatFrameReceived(udpConfig->FrameType, sequenceCounter, outOfOrder,
				  payloadMismatch, frameIdMismatch);

		if (outOfOrder) {
			if (!ignoreRxErrors)
				LogMessage(LOG_LEVEL_WARNING,
					   "Udp%sRx: frame[%" PRIu64
					   "] SequenceCounter mismatch: %" PRIu64 "!\n",
					   udpConfig->UdpSuffix, rxSequenceCounter,
					   sequenceCounter);
			sequenceCounter++;
		}

		sequenceCounter++;

		if (payloadMismatch)
			LogMessage(LOG_LEVEL_WARNING,
				   "Udp%sRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n",
				   udpConfig->UdpSuffix, rxSequenceCounter);

		/*
		 * If mirror enabled, assemble and store the frame for Tx later.
		 */
		if (!mirrorEnabled)
			continue;

		/*
		 * Store the new frame.
		 */
		RingBufferAdd(threadContext->MirrorBuffer, frame, len);

		pthread_mutex_lock(&threadContext->DataMutex);
		threadContext->NumFramesAvailable++;
		pthread_mutex_unlock(&threadContext->DataMutex);
	}

	return NULL;
}

static void *UdpTxGenerationThreadRoutine(void *data)
{
	struct ThreadContext *threadContext = data;
	const struct UdpThreadConfiguration *udpConfig = threadContext->PrivateData;
	pthread_mutex_t *mutex = &threadContext->DataMutex;
	uint64_t cycleTimeNS = udpConfig->UdpBurstPeriodNS;
	uint64_t numFrames = udpConfig->UdpNumFramesPerCycle;
	struct timespec wakeupTime;
	int ret;

	/*
	 * The UDP frames are generated by bursts with a certain period. This
	 * thread is responsible for generating it.
	 */

	ret = GetThreadStartTime(0, &wakeupTime);
	if (ret) {
		LogMessage(LOG_LEVEL_ERROR,
			   "Udp%sTxGen: Failed to calculate thread start time: %s!\n",
			   udpConfig->UdpSuffix, strerror(errno));
		return NULL;
	}

	while (!threadContext->Stop) {
		/* Wait until next period */
		IncrementPeriod(&wakeupTime, cycleTimeNS);

		do {
			ret = clock_nanosleep(appConfig.ApplicationClockId, TIMER_ABSTIME,
					      &wakeupTime, NULL);
		} while (ret == EINTR);

		if (ret) {
			LogMessage(LOG_LEVEL_ERROR, "Udp%sTxGen: clock_nanosleep() failed: %s\n",
				   udpConfig->UdpSuffix, strerror(ret));
			return NULL;
		}

		/* Generate frames */
		pthread_mutex_lock(mutex);
		threadContext->NumFramesAvailable = numFrames;
		pthread_mutex_unlock(mutex);
	}

	return NULL;
}

static int UdpThreadsCreate(struct ThreadContext *threadContext,
			    struct UdpThreadConfiguration *udpThreadConfig)
{
	char threadName[128];
	int ret;

	if (!strcmp(udpThreadConfig->UdpSuffix, "High") &&
	    !CONFIG_IS_TRAFFIC_CLASS_ACTIVE(UdpHigh)) {
		ret = 0;
		goto out;
	}
	if (!strcmp(udpThreadConfig->UdpSuffix, "Low") && !CONFIG_IS_TRAFFIC_CLASS_ACTIVE(UdpLow)) {
		ret = 0;
		goto out;
	}

	threadContext->PrivateData = udpThreadConfig;
	threadContext->SocketFd =
		CreateUDPSocket(udpThreadConfig->UdpDestination, udpThreadConfig->UdpSource,
				udpThreadConfig->UdpPort, udpThreadConfig->UdpSocketPriority,
				&threadContext->Destination);
	if (threadContext->SocketFd < 0) {
		fprintf(stderr, "Failed to create UdpSocket!\n");
		ret = -errno;
		goto err;
	}

	InitMutex(&threadContext->DataMutex);
	InitConditionVariable(&threadContext->DataCondVar);

	threadContext->TxFrameData = calloc(1, UDP_TX_FRAME_LENGTH);
	if (!threadContext->TxFrameData) {
		fprintf(stderr, "Failed to allocate Udp TxFrameData!\n");
		ret = -ENOMEM;
		goto err_tx;
	}

	if (udpThreadConfig->UdpRxMirrorEnabled) {
		/*
		 * Per period the expectation is: UdpNumFramesPerCycle * MAX_FRAME
		 */
		threadContext->MirrorBuffer = RingBufferAllocate(
			UDP_TX_FRAME_LENGTH * udpThreadConfig->UdpNumFramesPerCycle);
		if (!threadContext->MirrorBuffer) {
			fprintf(stderr, "Failed to allocate Udp Mirror RingBuffer!\n");
			ret = -ENOMEM;
			goto err_buffer;
		}
	}

	snprintf(threadName, sizeof(threadName), "Udp%sTxThread", udpThreadConfig->UdpSuffix);

	ret = CreateRtThread(&threadContext->TxTaskId, threadName,
			     udpThreadConfig->UdpTxThreadPriority, udpThreadConfig->UdpTxThreadCpu,
			     UdpTxThreadRoutine, threadContext);
	if (ret) {
		fprintf(stderr, "Failed to create Udp Tx Thread!\n");
		goto err_thread;
	}

	snprintf(threadName, sizeof(threadName), "Udp%sTxGenThread", udpThreadConfig->UdpSuffix);

	ret = CreateRtThread(&threadContext->TxGenTaskId, "UdpLowTxGenThread",
			     udpThreadConfig->UdpTxThreadPriority, udpThreadConfig->UdpTxThreadCpu,
			     UdpTxGenerationThreadRoutine, threadContext);
	if (ret) {
		fprintf(stderr, "Failed to create Udp TxGen Thread!\n");
		goto err_thread_txgen;
	}

	snprintf(threadName, sizeof(threadName), "Udp%sRxThread", udpThreadConfig->UdpSuffix);

	ret = CreateRtThread(&threadContext->RxTaskId, threadName,
			     udpThreadConfig->UdpRxThreadPriority, udpThreadConfig->UdpRxThreadCpu,
			     UdpRxThreadRoutine, threadContext);
	if (ret) {
		fprintf(stderr, "Failed to create Udp Rx Thread!\n");
		goto err_thread_rx;
	}

	return 0;

err_thread_rx:
	threadContext->Stop = 1;
	pthread_join(threadContext->TxGenTaskId, NULL);
err_thread_txgen:
	threadContext->Stop = 1;
	pthread_join(threadContext->TxTaskId, NULL);
err_thread:
	RingBufferFree(threadContext->MirrorBuffer);
err_buffer:
	free(threadContext->TxFrameData);
err_tx:
	close(threadContext->SocketFd);
err:
out:
	free(udpThreadConfig);
	return ret;
}

static void UdpThreadsFree(struct ThreadContext *threadContext)
{
	if (!threadContext)
		return;

	RingBufferFree(threadContext->MirrorBuffer);

	if (threadContext->SocketFd > 0)
		close(threadContext->SocketFd);

	free((void *)threadContext->PrivateData);
}

static void UdpThreadsStop(struct ThreadContext *threadContext)
{
	if (!threadContext)
		return;

	threadContext->Stop = 1;

	pthread_kill(threadContext->RxTaskId, SIGTERM);

	pthread_join(threadContext->RxTaskId, NULL);
	pthread_join(threadContext->TxTaskId, NULL);
	pthread_join(threadContext->TxGenTaskId, NULL);
}

static void UdpThreadsWaitForFinish(struct ThreadContext *threadContext)
{
	if (!threadContext)
		return;

	pthread_join(threadContext->RxTaskId, NULL);
	pthread_join(threadContext->TxTaskId, NULL);
	pthread_join(threadContext->TxGenTaskId, NULL);
}

int UdpLowThreadsCreate(struct ThreadContext *udpThreadContext)
{
	struct UdpThreadConfiguration *udpConfig;

	udpConfig = malloc(sizeof(*udpConfig));
	if (!udpConfig)
		return -ENOMEM;

	memset(udpConfig, '\0', sizeof(*udpConfig));
	udpConfig->FrameType = UDP_LOW_FRAME_TYPE;
	udpConfig->UdpSuffix = "Low";
	udpConfig->UdpRxMirrorEnabled = appConfig.UdpLowRxMirrorEnabled;
	udpConfig->UdpIgnoreRxErrors = appConfig.UdpLowIgnoreRxErrors;
	udpConfig->UdpBurstPeriodNS = appConfig.UdpLowBurstPeriodNS;
	udpConfig->UdpNumFramesPerCycle = appConfig.UdpLowNumFramesPerCycle;
	udpConfig->UdpPayloadPattern = appConfig.UdpLowPayloadPattern;
	udpConfig->UdpPayloadPatternLength = appConfig.UdpLowPayloadPatternLength;
	udpConfig->UdpFrameLength = appConfig.UdpLowFrameLength;
	udpConfig->UdpSocketPriority = appConfig.UdpLowSocketPriority;
	udpConfig->UdpTxThreadPriority = appConfig.UdpLowTxThreadPriority;
	udpConfig->UdpRxThreadPriority = appConfig.UdpLowRxThreadPriority;
	udpConfig->UdpTxThreadCpu = appConfig.UdpLowTxThreadCpu;
	udpConfig->UdpRxThreadCpu = appConfig.UdpLowRxThreadCpu;
	udpConfig->UdpPort = appConfig.UdpLowPort;
	udpConfig->UdpDestination = appConfig.UdpLowDestination;
	udpConfig->UdpSource = appConfig.UdpLowSource;

	return UdpThreadsCreate(udpThreadContext, udpConfig);
}

void UdpLowThreadsStop(struct ThreadContext *threadContext)
{
	UdpThreadsStop(threadContext);
}

void UdpLowThreadsFree(struct ThreadContext *threadContext)
{
	UdpThreadsFree(threadContext);
}

void UdpLowThreadsWaitForFinish(struct ThreadContext *threadContext)
{
	UdpThreadsWaitForFinish(threadContext);
}

int UdpHighThreadsCreate(struct ThreadContext *udpThreadContext)
{
	struct UdpThreadConfiguration *udpConfig;

	udpConfig = malloc(sizeof(*udpConfig));
	if (!udpConfig)
		return -ENOMEM;

	memset(udpConfig, '\0', sizeof(*udpConfig));
	udpConfig->FrameType = UDP_HIGH_FRAME_TYPE;
	udpConfig->UdpSuffix = "High";
	udpConfig->UdpRxMirrorEnabled = appConfig.UdpHighRxMirrorEnabled;
	udpConfig->UdpIgnoreRxErrors = appConfig.UdpHighIgnoreRxErrors;
	udpConfig->UdpBurstPeriodNS = appConfig.UdpHighBurstPeriodNS;
	udpConfig->UdpNumFramesPerCycle = appConfig.UdpHighNumFramesPerCycle;
	udpConfig->UdpPayloadPattern = appConfig.UdpHighPayloadPattern;
	udpConfig->UdpPayloadPatternLength = appConfig.UdpHighPayloadPatternLength;
	udpConfig->UdpFrameLength = appConfig.UdpHighFrameLength;
	udpConfig->UdpSocketPriority = appConfig.UdpHighSocketPriority;
	udpConfig->UdpTxThreadPriority = appConfig.UdpHighTxThreadPriority;
	udpConfig->UdpRxThreadPriority = appConfig.UdpHighRxThreadPriority;
	udpConfig->UdpTxThreadCpu = appConfig.UdpHighTxThreadCpu;
	udpConfig->UdpRxThreadCpu = appConfig.UdpHighRxThreadCpu;
	udpConfig->UdpPort = appConfig.UdpHighPort;
	udpConfig->UdpDestination = appConfig.UdpHighDestination;
	udpConfig->UdpSource = appConfig.UdpHighSource;

	return UdpThreadsCreate(udpThreadContext, udpConfig);
}

void UdpHighThreadsFree(struct ThreadContext *threadContext)
{
	UdpThreadsFree(threadContext);
}

void UdpHighThreadsStop(struct ThreadContext *threadContext)
{
	UdpThreadsStop(threadContext);
}

void UdpHighThreadsWaitForFinish(struct ThreadContext *threadContext)
{
	UdpThreadsWaitForFinish(threadContext);
}
