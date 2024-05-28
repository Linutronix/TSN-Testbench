// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_packet.h>

#include <sys/socket.h>

#include "log.h"
#include "packet.h"
#include "thread.h"
#include "tx_time.h"
#include "utils.h"

struct packet_context *packet_init(size_t num_frames_per_cycle)
{
	struct packet_context *context;

	context = calloc(1, sizeof(*context));
	if (!context) {
		fprintf(stderr, "Failed to allocate packet context!\n");
		return NULL;
	}

	context->frames = calloc(MAX_FRAME_SIZE * num_frames_per_cycle, sizeof(unsigned char));
	if (!context->frames) {
		fprintf(stderr, "Failed to allocate receive frame buffers!\n");
		goto err_frames;
	}

	context->iovecs = calloc(num_frames_per_cycle, sizeof(*context->iovecs));
	if (!context->iovecs) {
		fprintf(stderr, "Failed to allocate receive io vectors!\n");
		goto err_iovecs;
	}

	context->msgs = calloc(num_frames_per_cycle, sizeof(*context->msgs));
	if (!context->msgs) {
		fprintf(stderr, "Failed to allocate receive messages!\n");
		goto err_msgs;
	}

	context->num_frames_per_cycle = num_frames_per_cycle;

	return context;

err_msgs:
	free(context->iovecs);
err_iovecs:
	free(context->frames);
err_frames:
	free(context);

	return NULL;
}

void packet_free(struct packet_context *context)
{
	if (!context)
		return;

	free(context->frames);
	free(context->iovecs);
	free(context->msgs);
	free(context);
}

static inline uint64_t packet_get_sequence_counter(unsigned char *frame_data,
						   uint32_t meta_data_offset,
						   size_t num_frames_per_cycle)
{
	struct reference_meta_data *meta_data;

	meta_data = (struct reference_meta_data *)(frame_data + meta_data_offset);

	return meta_data_to_sequence_counter(meta_data, num_frames_per_cycle);
}

int packet_send_messages(struct packet_context *context, struct packet_send_request *send_req)
{
	struct iovec iovecs[send_req->num_frames];
	struct mmsghdr msgs[send_req->num_frames];
	int i, sent = 0;

	/* Prepare all messages to be sent. */
	memset(iovecs, '\0', send_req->num_frames * sizeof(struct iovec));
	memset(msgs, '\0', send_req->num_frames * sizeof(struct mmsghdr));
	for (i = 0; i < send_req->num_frames; i++) {
		unsigned char *frame;

		frame = send_req->mirror_enabled ? send_req->frame_data + i * send_req->frame_length
						 : frame_idx(send_req->frame_data, i);
		iovecs[i].iov_base = frame;
		iovecs[i].iov_len = send_req->frame_length;
		msgs[i].msg_hdr.msg_iov = &iovecs[i];
		msgs[i].msg_hdr.msg_iovlen = 1;
		msgs[i].msg_hdr.msg_name = send_req->destination;
		msgs[i].msg_hdr.msg_namelen = sizeof(*send_req->destination);

		/* In case the user configured Tx Time also add it. */
		if (send_req->tx_time_enabled) {
			char control[CMSG_SPACE(sizeof(uint64_t))] = {0};
			uint64_t tx_time, sequence_counter;
			struct cmsghdr *cmsg;

			sequence_counter = packet_get_sequence_counter(
				frame, send_req->meta_data_offset, context->num_frames_per_cycle);
			tx_time = tx_time_get_frame_tx_time(
				send_req->wakeup_time, sequence_counter, send_req->duration,
				context->num_frames_per_cycle, send_req->tx_time_offset,
				send_req->traffic_class);

			cmsg = CMSG_FIRSTHDR(&msgs[i].msg_hdr);
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SO_TXTIME;
			cmsg->cmsg_len = CMSG_LEN(sizeof(int64_t));
			*((uint64_t *)CMSG_DATA(cmsg)) = tx_time;

			msgs[i].msg_hdr.msg_control = control;
			msgs[i].msg_hdr.msg_controllen = sizeof(control);
		}
	}

	/* Send them. */
	while (sent < send_req->num_frames) {
		int len;

		len = sendmmsg(send_req->socket_fd, &msgs[sent], send_req->num_frames - sent, 0);
		if (len == -1) {
			log_message(LOG_LEVEL_ERROR, "%sTx: sendmmsg() failed: %s\n",
				    send_req->traffic_class, strerror(errno));
			return -errno;
		}

		sent += len;
	}

	return sent;
}

int packet_receive_messages(struct packet_context *context, struct packet_receive_request *recv_req)
{
	int received = 0;

	while (true) {
		struct iovec *iovecs = context->iovecs;
		struct mmsghdr *msgs = context->msgs;
		int i, len;

		for (i = 0; i < context->num_frames_per_cycle; i++) {
			iovecs[i].iov_base = frame_idx(context->frames, i);
			iovecs[i].iov_len = MAX_FRAME_SIZE;
			msgs[i].msg_hdr.msg_iov = &iovecs[i];
			msgs[i].msg_hdr.msg_iovlen = 1;
		}

		len = recvmmsg(recv_req->socket_fd, msgs, context->num_frames_per_cycle, 0, NULL);
		if (len == -1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				log_message(LOG_LEVEL_ERROR, "%sRx: recvmmsg() failed: %s\n",
					    recv_req->traffic_class, strerror(errno));
				continue;
			} else {
				/* No more frames. Comeback within next period. */
				break;
			}
		}

		/* Process received frames. */
		for (i = 0; i < len; i++)
			recv_req->receive_function(recv_req->data, frame_idx(context->frames, i),
						   msgs[i].msg_len);

		received += len;
	}

	return received;
}
