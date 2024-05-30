/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _UDP_THREAD_H_
#define _UDP_THREAD_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <pthread.h>

#include "stat.h"
#include "thread.h"

struct udp_thread_configuration {
	/* UDP configuration */
	enum stat_frame_type frame_type;
	const char *traffic_class;
	bool udp_rx_mirror_enabled;
	bool udp_ignore_rx_errors;
	uint64_t udp_burst_period_ns;
	size_t udp_num_frames_per_cycle;
	const char *udp_payload_pattern;
	size_t udp_payload_pattern_length;
	size_t udp_frame_length;
	int udp_socket_priority;
	int udp_tx_thread_priority;
	int udp_rx_thread_priority;
	int udp_tx_thread_cpu;
	int udp_rx_thread_cpu;
	const char *udp_port;
	const char *udp_destination;
	const char *udp_source;
};

int udp_low_threads_create(struct thread_context *thread_context);
void udp_low_threads_free(struct thread_context *thread_context);
void udp_low_threads_wait_for_finish(struct thread_context *thread_context);

int udp_high_threads_create(struct thread_context *thread_context);
void udp_high_threads_free(struct thread_context *thread_context);
void udp_high_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _UDP_THREAD_H_ */
