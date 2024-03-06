/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _TSN_THREAD_H_
#define _TSN_THREAD_H_

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include <linux/if_ether.h>

#include "security.h"
#include "stat.h"
#include "thread.h"
#include "xdp.h"

#define TSN_TX_FRAME_LENGTH XDP_FRAME_SIZE

struct tsn_thread_configuration {
	/* TSN configuration */
	enum stat_frame_type frame_type;
	const char *tsn_suffix;
	bool tsn_tx_enabled;
	bool tsn_rx_enabled;
	bool tsn_rx_mirror_enabled;
	bool tsn_xdp_enabled;
	bool tsn_xdp_skb_mode;
	bool tsn_xdp_zc_mode;
	bool tsn_xdp_wakeup_mode;
	bool tsn_xdp_busy_poll_mode;
	bool tsn_tx_time_enabled;
	bool tsn_ignore_rx_errors;
	uint64_t tsn_tx_time_offset_ns;
	size_t tsn_num_frames_per_cycle;
	const char *tsn_payload_pattern;
	size_t tsn_payload_pattern_length;
	size_t tsn_frame_length;
	enum security_mode tsn_security_mode;
	enum security_algorithm tsn_security_algorithm;
	char *tsn_security_key;
	size_t tsn_security_key_length;
	char *tsn_security_iv_prefix;
	size_t tsn_security_iv_prefix_length;
	int tsn_rx_queue;
	int tsn_tx_queue;
	int tsn_socket_priority;
	int tsn_tx_thread_priority;
	int tsn_rx_thread_priority;
	int tsn_tx_thread_cpu;
	int tsn_rx_thread_cpu;
	const char *tsn_interface;
	const unsigned char *tsn_destination;
	/* Socket create function */
	int (*create_tsn_socket)(void);
	/* TSN low/high specific */
	int vlan_id;
	int vlan_pcp;
	int frame_id_range_start;
	int frame_id_range_end;
};

int tsn_high_threads_create(struct thread_context *thread_context);
void tsn_high_threads_stop(struct thread_context *thread_context);
void tsn_high_threads_free(struct thread_context *thread_context);
void tsn_high_threads_wait_for_finish(struct thread_context *thread_context);

int tsn_low_threads_create(struct thread_context *thread_context);
void tsn_low_threads_stop(struct thread_context *thread_context);
void tsn_low_threads_free(struct thread_context *thread_context);
void tsn_low_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _TSN_THREAD_H_ */
