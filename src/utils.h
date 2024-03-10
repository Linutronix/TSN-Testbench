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

static inline void ns_to_ts(int64_t ns, struct timespec *ts)
{
	ts->tv_sec = ns / NSEC_PER_SEC;
	ts->tv_nsec = ns % NSEC_PER_SEC;
}

static inline int64_t ts_to_ns(const struct timespec *ts)
{
	return ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec;
}

void increment_period(struct timespec *time, int64_t period_ns);

void swap_mac_addresses(void *buffer, size_t len);
void insert_vlan_tag(void *buffer, size_t len, uint16_t vlan_tci);

/*
 * This function takes an received Ethernet frame by AF_PACKET sockets and performs two tasks:
 *
 *  1.) Inject VLAN header
 *  2.) Swap source and destination
 *
 * This function does nothing when the @newFrame isn't sufficent in length.
 */
void build_vlan_frame_from_rx(const unsigned char *old_frame, size_t old_frame_len,
			      unsigned char *new_frame, size_t new_frame_len, uint16_t ether_type,
			      uint16_t vlan_tci);

/*
 * This function initializes an PROFINET Ethernet frame. The Ethernet header, PROFINET header and
 * payload is initialized. The sequenceCounter is set to zero.
 *
 * In case the SecurityMode is AE or AO, the PROFINET Ethernet frames will contain the
 * SecurityHeader after the FrameID.
 */
void initialize_profinet_frame(enum security_mode mode, unsigned char *frame_data,
			       size_t frame_length, const unsigned char *source,
			       const unsigned char *destination, const char *payload_pattern,
			       size_t payload_pattern_length, uint16_t vlan_tci, uint16_t frame_id);

/*
 * The following function prepares an already initialized PROFINET Ethernet frame for final
 * transmission. Depending on traffic class and security modes, different actions have to be taken
 * e.g., adjusting the cycle counter and perform authentifcation and/or encryption.
 */

struct prepare_frame_config {
	enum security_mode mode;
	struct security_context *security_context;
	const unsigned char *iv_prefix;
	const unsigned char *payload_pattern;
	size_t payload_pattern_length;
	unsigned char *frame_data;
	size_t frame_length;
	size_t num_frames_per_cycle;
	uint64_t sequence_counter;
	uint32_t meta_data_offset;
};

int prepare_frame_for_tx(const struct prepare_frame_config *frame_config);

void prepare_iv(const unsigned char *iv_prefix, uint64_t sequence_counter, struct security_iv *iv);

void prepare_openssl(struct security_context *context);

int get_thread_start_time(uint64_t base_offset, struct timespec *wakeup_time);

void configure_cpu_latency(void);
void restore_cpu_latency(void);

/* error handling */
void pthread_error(int ret, const char *message);

/* Printing */
void print_mac_address(const unsigned char *mac_address);
void print_payload_pattern(const char *payload_pattern, size_t payload_pattern_length);

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define BIT(x) (1ULL << (x))

/* Meta data handling */
static inline uint64_t meta_data_to_sequence_counter(const struct reference_meta_data *meta,
						     size_t num_frames_per_cycle)
{
	uint32_t frame_counter, cycle_counter;

	frame_counter = be32toh(meta->frame_counter);
	cycle_counter = be32toh(meta->cycle_counter);

	return (uint64_t)cycle_counter * num_frames_per_cycle + frame_counter;
}

static inline void sequence_counter_to_meta_data(struct reference_meta_data *meta,
						 uint64_t sequence_counter,
						 size_t num_frames_per_cycle)
{
	meta->frame_counter = htobe32(sequence_counter % num_frames_per_cycle);
	meta->cycle_counter = htobe32(sequence_counter / num_frames_per_cycle);
}

#endif /* _UTILS_H_ */
