// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ring_buffer.h"
#include "thread.h"

struct RingBuffer *RingBufferAllocate(size_t bufferSize)
{
	struct RingBuffer *ringBuffer = malloc(sizeof(*ringBuffer));

	if (!ringBuffer)
		return NULL;

	memset(ringBuffer, '\0', sizeof(*ringBuffer));

	ringBuffer->Data = malloc(bufferSize);
	if (!ringBuffer->Data) {
		free(ringBuffer);
		return NULL;
	}

	memset(ringBuffer->Data, '\0', bufferSize);

	ringBuffer->BufferSize = bufferSize;
	ringBuffer->BufferWritePointer = ringBuffer->Data;
	ringBuffer->BufferReadPointer = ringBuffer->Data;

	InitMutex(&ringBuffer->DataMutex);

	return ringBuffer;
}

void RingBufferFree(struct RingBuffer *ringBuffer)
{
	if (!ringBuffer)
		return;

	free(ringBuffer->Data);
	free(ringBuffer);
}

void RingBufferAdd(struct RingBuffer *ringBuffer, const unsigned char *data, size_t len)
{
	size_t available;

	if (!ringBuffer)
		return;

	if (len > ringBuffer->BufferSize)
		return;

	pthread_mutex_lock(&ringBuffer->DataMutex);

	/* Wrap? */
	available = (ringBuffer->Data + ringBuffer->BufferSize) - ringBuffer->BufferWritePointer;
	if (len <= available) {
		memcpy(ringBuffer->BufferWritePointer, data, len);
		ringBuffer->BufferWritePointer += len;
	} else {
		memcpy(ringBuffer->BufferWritePointer, data, available);
		len -= available;
		data += available;
		ringBuffer->BufferWritePointer = ringBuffer->Data;
		memcpy(ringBuffer->BufferWritePointer, data, len);
		ringBuffer->BufferWritePointer += len;
	}

	if ((ringBuffer->Data + ringBuffer->BufferSize) == ringBuffer->BufferWritePointer)
		ringBuffer->BufferWritePointer = ringBuffer->Data;

	pthread_mutex_unlock(&ringBuffer->DataMutex);
}

void RingBufferFetch(struct RingBuffer *ringBuffer, unsigned char *data, size_t len, size_t *outLen)
{
	intptr_t available;
	size_t realLen;

	if (!ringBuffer)
		return;

	if (len > ringBuffer->BufferSize)
		return;

	pthread_mutex_lock(&ringBuffer->DataMutex);

	available = ringBuffer->BufferWritePointer - ringBuffer->BufferReadPointer;

	/* Simple case: Copy difference between read and write ptr. */
	if (available > 0) {
		realLen = available > len ? len : available;
		memcpy(data, ringBuffer->BufferReadPointer, realLen);
		*outLen = realLen;
		ringBuffer->BufferReadPointer += realLen;
	} else if (available < 0) {
		/* Copy first part */
		available =
			(ringBuffer->Data + ringBuffer->BufferSize) - ringBuffer->BufferReadPointer;
		realLen = available > len ? len : available;
		memcpy(data, ringBuffer->BufferReadPointer, realLen);

		len -= realLen;
		data += realLen;
		*outLen = realLen;
		ringBuffer->BufferReadPointer += realLen;

		if (ringBuffer->BufferReadPointer == (ringBuffer->Data + ringBuffer->BufferSize))
			ringBuffer->BufferReadPointer = ringBuffer->Data;

		/* Copy second part */
		if (len > 0) {
			available = ringBuffer->BufferWritePointer - ringBuffer->BufferReadPointer;
			realLen = available > len ? len : available;

			memcpy(data, ringBuffer->BufferReadPointer, realLen);

			ringBuffer->BufferReadPointer += realLen;
			*outLen += realLen;
		}
	} else {
		*outLen = 0;
	}

	if (ringBuffer->BufferReadPointer == (ringBuffer->Data + ringBuffer->BufferSize))
		ringBuffer->BufferReadPointer = ringBuffer->Data;

	pthread_mutex_unlock(&ringBuffer->DataMutex);
}
