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

struct packet_context {
	unsigned char *frames;
	struct iovec *iovecs;
	struct mmsghdr *msgs;
	size_t num_frames_per_cycle;
};

struct packet_context *packet_init(size_t num_frames_per_cycle);
void packet_free(struct packet_context *context);

struct packet_send_request {
	const char *traffic_class;
	int socket_fd;
	struct sockaddr_ll *destination;
	unsigned char *frame_data;
	size_t num_frames;
	size_t frame_length;
	uint64_t wakeup_time;
	uint64_t duration;
	uint64_t tx_time_offset;
	uint32_t meta_data_offset;
	bool mirror_enabled;
	bool tx_time_enabled;
};

int packet_send_messages(struct packet_context *context, struct packet_send_request *send_req);

struct packet_receive_request {
	const char *traffic_class;
	int socket_fd;
	int (*receive_function)(void *data, unsigned char *, size_t);
	void *data;
};

int packet_receive_messages(struct packet_context *context,
			    struct packet_receive_request *recv_req);

#endif /* PACKET_H */
