/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _RING_BUFFER_H_
#define _RING_BUFFER_H_

#include <pthread.h>

/*
 * There is the need for concurrent circular buffers with this code e.g. for:
 *  a) Packet/Frame buffering
 *  b) Logging
 *
 * Introduce a "generic" ring buffer suitable for both scenarios.
 */
struct RingBuffer {
	size_t BufferSize;
	unsigned char *BufferWritePointer;
	unsigned char *BufferReadPointer;
	unsigned char *Data;
	pthread_mutex_t DataMutex;
};

struct RingBuffer *RingBufferAllocate(size_t bufferSize);
void RingBufferAdd(struct RingBuffer *ringBuffer, const unsigned char *data, size_t len);
void RingBufferFetch(struct RingBuffer *ringBuffer, unsigned char *data, size_t len,
		     size_t *outLen);
void RingBufferFree(struct RingBuffer *ringBuffer);

#endif /* _RING_BUFFER_H_ */
