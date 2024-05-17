/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct packet_send_request {
	const char *traffic_class;
	int socket_fd;
	struct sockaddr_ll *destination;
	unsigned char *frame_data;
	size_t num_frames;
	size_t num_frames_per_cycle;
	size_t frame_length;
	uint64_t wakeup_time;
	uint64_t duration;
	uint64_t tx_time_offset;
	uint32_t meta_data_offset;
	bool mirror_enabled;
	bool tx_time_enabled;
};

int packet_send_messages(struct packet_send_request *send_req);
int packet_receive_messages();

#endif /* PACKET_H */
