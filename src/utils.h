/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "net_def.h"
#include "security.h"

/* timing */
#define NSEC_PER_SEC 1000000000LL

static inline void NsToTs(int64_t ns, struct timespec *ts)
{
	ts->tv_sec = ns / NSEC_PER_SEC;
	ts->tv_nsec = ns % NSEC_PER_SEC;
}

static inline int64_t TsToNs(const struct timespec *ts)
{
	return ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;
}

void IncrementPeriod(struct timespec *time, int64_t periodNS);

void SwapMacAddresses(void *buffer, size_t len);
void InsertVlanTag(void *buffer, size_t len, uint16_t vlanTCI);

/*
 * This function takes an received Ethernet frame by AF_PACKET sockets and
 * performs two tasks:
 *
 *  1.) Inject VLAN header
 *  2.) Swap source and destination
 *
 * This function does nothing when the @newFrame isn't sufficent in length.
 */
void BuildVLANFrameFromRx(const unsigned char *oldFrame, size_t oldFrameLen,
			  unsigned char *newFrame, size_t newFrameLen, uint16_t etherType,
			  uint16_t vlanTCI);

/*
 * This function initializes an PROFINET Ethernet frame. The Ethernet header,
 * PROFINET header and payload is initialized. The sequenceCounter is set to zero.
 *
 * In case the SecurityMode is AE or AO, the PROFINET Ethernet frames will contain the
 * SecurityHeader after the FrameID.
 */
void InitializeProfinetFrame(enum SecurityMode mode, unsigned char *frameData, size_t frameLength,
			     const unsigned char *source, const unsigned char *destination,
			     const char *payloadPattern, size_t payloadPatternLength,
			     uint16_t vlanTCI, uint16_t frameId);

/*
 * The following function prepares an already initialized PROFINET Ethernet frame for final
 * transmission. Depending on traffic class and security modes, different actions have to be taken
 * e.g., adjusting the cycle counter and perform authentifcation and/or encryption.
 */

struct PrepareFrameConfig {
	enum SecurityMode Mode;
	struct SecurityContext *SecurityContext;
	const unsigned char *IvPrefix;
	const unsigned char *PayloadPattern;
	size_t PayloadPatternLength;
	unsigned char *FrameData;
	size_t FrameLength;
	size_t NumFramesPerCycle;
	uint64_t SequenceCounter;
	uint32_t MetaDataOffset;
};

int PrepareFrameForTx(const struct PrepareFrameConfig *frameConfig);

void PrepareIv(const unsigned char *ivPrefix, uint64_t sequenceCounter, struct SecurityIv *iv);

void PrepareOpenssl(struct SecurityContext *context);

int GetThreadStartTime(uint64_t baseOffset, struct timespec *wakeupTime);

void ConfigureCpuLatency(void);
void RestoreCpuLatency(void);

/* error handling */
void PthreadError(int ret, const char *message);

/* Printing */
void PrintMacAddress(const unsigned char *macAddress);
void PrintPayloadPattern(const char *payloadPattern, size_t payloadPatternLength);

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define BIT(x) (1ULL << (x))

/* Meta data handling */
static inline uint64_t MetaDataToSequenceCounter(const struct ReferenceMetaData *meta,
						 size_t numFramesPerCycle)
{
	uint32_t frameCounter, cycleCounter;

	frameCounter = be32toh(meta->FrameCounter);
	cycleCounter = be32toh(meta->CycleCounter);

	return (uint64_t)cycleCounter * numFramesPerCycle + frameCounter;
}

static inline void SequenceCounterToMetaData(struct ReferenceMetaData *meta,
					     uint64_t sequenceCounter, size_t numFramesPerCycle)
{
	meta->FrameCounter = htobe32(sequenceCounter % numFramesPerCycle);
	meta->CycleCounter = htobe32(sequenceCounter / numFramesPerCycle);
}

#endif /* _UTILS_H_ */
