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
#include "dcp_thread.h"
#include "log.h"
#include "net.h"
#include "security.h"
#include "stat.h"
#include "utils.h"

static void dcp_build_frame_from_rx(const unsigned char *old_frame, size_t old_frame_len,
				    unsigned char *new_frame, size_t new_frame_len,
				    const unsigned char *source)
{
	struct vlan_ethernet_header *eth_new, *eth_old;

	/*
	 * Two tasks:
	 *  -> Keep destination and adjust source
	 *  -> Inject VLAN header
	 */

	if (new_frame_len < old_frame_len + sizeof(struct vlan_header))
		return;

	/* Copy payload */
	memcpy(new_frame + ETH_ALEN * 2 + sizeof(struct vlan_header), old_frame + ETH_ALEN * 2,
	       old_frame_len - ETH_ALEN * 2);

	/* Swap source destination */
	eth_new = (struct vlan_ethernet_header *)new_frame;
	eth_old = (struct vlan_ethernet_header *)old_frame;

	memcpy(eth_new->destination, eth_old->destination, ETH_ALEN);
	memcpy(eth_new->source, source, ETH_ALEN);

	/* Inject VLAN info */
	eth_new->vlan_proto = htons(ETH_P_8021Q);
	eth_new->vlantci = htons(app_config.dcp_vid | DCP_PCP_VALUE << VLAN_PCP_SHIFT);
	eth_new->vlan_encapsulated_proto = htons(ETH_P_PROFINET_RT);
}

static void dcp_send_frame(const unsigned char *frame_data, size_t frame_length,
			   size_t num_frames_per_cycle, int socket_fd)
{
	struct vlan_ethernet_header *eth;
	struct profinet_rt_header *rt;
	uint64_t sequence_counter;
	ssize_t ret;

	/* Fetch meta data */
	rt = (struct profinet_rt_header *)(frame_data + sizeof(*eth));
	sequence_counter = meta_data_to_sequence_counter(&rt->meta_data, num_frames_per_cycle);

	/* Send it */
	ret = send(socket_fd, frame_data, frame_length, 0);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "DcpTx: send() for %" PRIu64 " failed: %s\n",
			    sequence_counter, strerror(errno));
		return;
	}

	stat_frame_sent(DCP_FRAME_TYPE, sequence_counter);
}

static void dcp_gen_and_send_frame(unsigned char *frame_data, size_t frame_length,
				   size_t num_frames_per_cycle, int socket_fd,
				   uint64_t sequence_counter)
{
	struct vlan_ethernet_header *eth;
	struct profinet_rt_header *rt;
	ssize_t ret;

	/* Adjust meta data */
	rt = (struct profinet_rt_header *)(frame_data + sizeof(*eth));
	sequence_counter_to_meta_data(&rt->meta_data, sequence_counter, num_frames_per_cycle);

	/* Send it */
	ret = send(socket_fd, frame_data, frame_length, 0);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "DcpTx: send() for %" PRIu64 " failed: %s\n",
			    sequence_counter, strerror(errno));
		return;
	}

	stat_frame_sent(DCP_FRAME_TYPE, sequence_counter);
}

static void *dcp_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	unsigned char received_frames[DCP_TX_FRAME_LENGTH * app_config.dcp_num_frames_per_cycle];
	const bool mirror_enabled = app_config.dcp_rx_mirror_enabled;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	pthread_cond_t *cond = &thread_context->data_cond_var;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	unsigned char *frame;
	int ret, socket_fd;

	socket_fd = thread_context->socket_fd;

	ret = get_interface_mac_address(app_config.dcp_interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "DcpTx: Failed to get Source MAC address!\n");
		return NULL;
	}

	frame = thread_context->tx_frame_data;
	initialize_profinet_frame(SECURITY_MODE_NONE, frame, DCP_TX_FRAME_LENGTH, source,
				  app_config.dcp_destination, app_config.dcp_payload_pattern,
				  app_config.dcp_payload_pattern_length,
				  app_config.dcp_vid | DCP_PCP_VALUE << VLAN_PCP_SHIFT, 0xfefe);

	while (!thread_context->stop) {
		size_t num_frames, i;

		/*
		 * Wait until signalled. These DCP frames have to be sent after
		 * the RTA frames. Therefore, the RTA TxThread signals this one
		 * here.
		 */
		pthread_mutex_lock(mutex);
		pthread_cond_wait(cond, mutex);
		num_frames = thread_context->num_frames_available;
		thread_context->num_frames_available = 0;
		pthread_mutex_unlock(mutex);

		/*
		 * Send DcpFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			/* Send DcpFrames */
			for (i = 0; i < num_frames; ++i)
				dcp_gen_and_send_frame(frame, app_config.dcp_frame_length,
						       app_config.dcp_num_frames_per_cycle,
						       socket_fd, sequence_counter++);
		} else {
			size_t len;

			ring_buffer_fetch(thread_context->mirror_buffer, received_frames,
					  sizeof(received_frames), &len);

			/* Len should be a multiple of frame size */
			for (i = 0; i < len / app_config.dcp_frame_length; ++i)
				dcp_send_frame(received_frames + i * app_config.dcp_frame_length,
					       app_config.dcp_frame_length,
					       app_config.dcp_num_frames_per_cycle, socket_fd);

			pthread_mutex_lock(&thread_context->data_mutex);
			thread_context->num_frames_available = 0;
			pthread_mutex_unlock(&thread_context->data_mutex);
		}

		/* Signal next Tx thread */
		if (thread_context->next) {
			pthread_mutex_lock(&thread_context->next->data_mutex);
			if (thread_context->next->num_frames_available)
				pthread_cond_signal(&thread_context->next->data_cond_var);
			pthread_mutex_unlock(&thread_context->next->data_mutex);
		}
	}

	return NULL;
}

static int dcp_rx_frame(struct thread_context *thread_context, unsigned char *frame_data,
			size_t len)
{
	const unsigned char *expected_pattern =
		(const unsigned char *)app_config.dcp_payload_pattern;
	const size_t expected_pattern_length = app_config.dcp_payload_pattern_length;
	const size_t num_frames_per_cycle = app_config.dcp_num_frames_per_cycle;
	const bool mirror_enabled = app_config.dcp_rx_mirror_enabled;
	const bool ignore_rx_errors = app_config.dcp_ignore_rx_errors;
	const size_t frame_length = app_config.dcp_frame_length;
	bool out_of_order, payload_mismatch, frame_id_mismatch;
	unsigned char new_frame[DCP_TX_FRAME_LENGTH];
	struct profinet_rt_header *rt;
	uint64_t sequence_counter;

	if (len != frame_length - 4) {
		log_message(LOG_LEVEL_ERROR, "DcpRx: Frame with wrong length received!\n");
		return -EINVAL;
	}

	/*
	 * Check cycle counter and payload. The frame id range is checked by the
	 * attached BPF filter.
	 */
	rt = (struct profinet_rt_header *)(frame_data + sizeof(struct ethhdr));
	sequence_counter = meta_data_to_sequence_counter(&rt->meta_data, num_frames_per_cycle);

	out_of_order = sequence_counter != thread_context->rx_sequence_counter;
	payload_mismatch = memcmp(frame_data + sizeof(struct ethhdr) + sizeof(*rt),
				  expected_pattern, expected_pattern_length);
	frame_id_mismatch = false;

	stat_frame_received(DCP_FRAME_TYPE, sequence_counter, out_of_order, payload_mismatch,
			    frame_id_mismatch);

	if (out_of_order) {
		if (!ignore_rx_errors)
			log_message(LOG_LEVEL_WARNING,
				    "DcpRx: frame[%" PRIu64 "] SequenceCounter mismatch: %" PRIu64
				    "!\n",
				    sequence_counter, thread_context->rx_sequence_counter);
		thread_context->rx_sequence_counter++;
	}

	if (payload_mismatch)
		log_message(LOG_LEVEL_WARNING,
			    "DcpRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n",
			    sequence_counter);

	thread_context->rx_sequence_counter++;

	/*
	 * If mirror enabled, assemble and store the frame for Tx later.
	 */
	if (!mirror_enabled)
		return 0;

	/*
	 * Build new frame for Tx with VLAN info.
	 */
	dcp_build_frame_from_rx(frame_data, len, new_frame, sizeof(new_frame),
				thread_context->source);

	/*
	 * Store the new frame.
	 */
	ring_buffer_add(thread_context->mirror_buffer, new_frame, len + sizeof(struct vlan_header));

	pthread_mutex_lock(&thread_context->data_mutex);
	thread_context->num_frames_available++;
	pthread_mutex_unlock(&thread_context->data_mutex);

	return 0;
}

static void *dcp_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	unsigned char frame[DCP_TX_FRAME_LENGTH];
	int socket_fd;

	socket_fd = thread_context->socket_fd;

	while (!thread_context->stop) {
		ssize_t len;

		/* Wait for DCP frame */
		len = recv(socket_fd, frame, sizeof(frame), 0);
		if (len < 0) {
			log_message(LOG_LEVEL_ERROR, "DcpRx: recv() failed: %s\n", strerror(errno));
			return NULL;
		}
		if (len == 0)
			return NULL;

		dcp_rx_frame(thread_context, frame, len);
	}

	return NULL;
}

static void *dcp_tx_generation_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	uint64_t num_frames = app_config.dcp_num_frames_per_cycle;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	uint64_t cycle_time_ns = app_config.dcp_burst_period_ns;
	struct timespec wakeup_time;
	int ret;

	/*
	 * The DCP frames are generated by bursts with a certain period. This
	 * thread is responsible for generating it.
	 */

	ret = get_thread_start_time(0, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "DcpTxGen: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		/* Wait until next period */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "DcpTxGen: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		/* Generate frames */
		pthread_mutex_lock(mutex);
		thread_context->num_frames_available = num_frames;
		pthread_mutex_unlock(mutex);
	}

	return NULL;
}

int dcp_threads_create(struct thread_context *thread_context)
{
	int ret;

	if (!CONFIG_IS_TRAFFIC_CLASS_ACTIVE(dcp))
		goto out;

	thread_context->socket_fd = create_dcp_socket();
	if (thread_context->socket_fd < 0) {
		fprintf(stderr, "Failed to create DcpSocket!\n");
		ret = -ENOMEM;
		goto err;
	}

	init_mutex(&thread_context->data_mutex);
	init_condition_variable(&thread_context->data_cond_var);

	thread_context->tx_frame_data = calloc(1, DCP_TX_FRAME_LENGTH);
	if (!thread_context->tx_frame_data) {
		fprintf(stderr, "Failed to allocate Dcp TxFrameData!\n");
		ret = -ENOMEM;
		goto err_tx;
	}

	ret = get_interface_mac_address(app_config.dcp_interface, thread_context->source,
					sizeof(thread_context->source));
	if (ret < 0) {
		fprintf(stderr, "Failed to get Dcp Source MAC address!\n");
		goto err_mac;
	}

	if (app_config.dcp_rx_mirror_enabled) {
		/*
		 * Per period the expectation is: DcpNumFramesPerCycle * MAX_FRAME
		 */
		thread_context->mirror_buffer = ring_buffer_allocate(
			DCP_TX_FRAME_LENGTH * app_config.dcp_num_frames_per_cycle);
		if (!thread_context->mirror_buffer) {
			fprintf(stderr, "Failed to allocate Dcp Mirror RingBuffer!\n");
			ret = -ENOMEM;
			goto err_mac;
		}
	}

	ret = create_rt_thread(&thread_context->tx_task_id, "DcpTxThread",
			       app_config.dcp_tx_thread_priority, app_config.dcp_tx_thread_cpu,
			       dcp_tx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Dcp Tx Thread!\n");
		goto err_thread;
	}

	ret = create_rt_thread(&thread_context->tx_gen_task_id, "DcpTxGenThread",
			       app_config.dcp_tx_thread_priority, app_config.dcp_tx_thread_cpu,
			       dcp_tx_generation_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Dcp Tx Thread!\n");
		goto err_thread_txgen;
	}

	ret = create_rt_thread(&thread_context->rx_task_id, "DcpRxThread",
			       app_config.dcp_rx_thread_priority, app_config.dcp_rx_thread_cpu,
			       dcp_rx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Dcp Rx Thread!\n");
		goto err_thread_rx;
	}

out:
	return 0;

err_thread_rx:
	thread_context->stop = 1;
	pthread_join(thread_context->tx_gen_task_id, NULL);
err_thread_txgen:
	thread_context->stop = 1;
	pthread_join(thread_context->tx_task_id, NULL);
err_thread:
	ring_buffer_free(thread_context->mirror_buffer);
err_mac:
	free(thread_context->tx_frame_data);
err_tx:
	close(thread_context->socket_fd);
err:
	return ret;
}

void dcp_threads_free(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	ring_buffer_free(thread_context->mirror_buffer);

	if (thread_context->socket_fd > 0)
		close(thread_context->socket_fd);
}

void dcp_threads_stop(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	thread_context->stop = 1;

	pthread_kill(thread_context->rx_task_id, SIGTERM);

	pthread_join(thread_context->rx_task_id, NULL);
	pthread_join(thread_context->tx_task_id, NULL);
	pthread_join(thread_context->tx_gen_task_id, NULL);
}

void dcp_threads_wait_for_finish(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	pthread_join(thread_context->rx_task_id, NULL);
	pthread_join(thread_context->tx_task_id, NULL);
	pthread_join(thread_context->tx_gen_task_id, NULL);
}
