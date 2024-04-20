// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>

#include "config.h"
#include "lldp_thread.h"
#include "log.h"
#include "net.h"
#include "net_def.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

static void lldp_build_frame_from_rx(unsigned char *frame_data, const unsigned char *source)
{
	struct ethhdr *eth = (struct ethhdr *)frame_data;

	/* One task: Swap source. */
	memcpy(eth->h_source, source, ETH_ALEN);
}

static void lldp_initialize_frame(unsigned char *frame_data, const unsigned char *source,
				  const unsigned char *destination)
{
	struct reference_meta_data *meta;
	size_t payload_offset;
	struct ethhdr *eth;

	/*
	 * LldpFrame:
	 *   Destination (multicast)
	 *   Source
	 *   Ether type: 88cc
	 *   Cycle counter
	 *   Payload
	 *   Padding to maxFrame
	 */

	eth = (struct ethhdr *)frame_data;

	/* Ethernet header */
	memcpy(eth->h_dest, destination, ETH_ALEN);
	memcpy(eth->h_source, source, ETH_ALEN);
	eth->h_proto = htons(ETH_P_LLDP);

	/* Payload: SequenceCounter + Data */
	meta = (struct reference_meta_data *)(frame_data + sizeof(*eth));
	memset(meta, '\0', sizeof(*meta));
	payload_offset = sizeof(*eth) + sizeof(*meta);
	memcpy(frame_data + payload_offset, app_config.lldp_payload_pattern,
	       app_config.lldp_payload_pattern_length);

	/* Padding: '\0' */
}

static void lldp_send_frame(const unsigned char *frame_data, size_t frame_length,
			    size_t num_frames_per_cycle, int socket_fd)
{
	struct reference_meta_data *meta;
	uint64_t sequence_counter;
	struct ethhdr *eth;
	ssize_t ret;

	/* Fetch meta data */
	meta = (struct reference_meta_data *)(frame_data + sizeof(*eth));
	sequence_counter = meta_data_to_sequence_counter(meta, num_frames_per_cycle);

	/* Send it */
	ret = send(socket_fd, frame_data, frame_length, 0);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "LldpTx: send() for %" PRIu64 " failed: %s\n",
			    sequence_counter, strerror(errno));
		return;
	}

	stat_frame_sent(LLDP_FRAME_TYPE, sequence_counter);
}

static void lldp_gen_and_send_frame(unsigned char *frame_data, size_t frame_length,
				    size_t num_frames_per_cycle, int socket_fd,
				    uint64_t sequence_counter)
{
	struct reference_meta_data *meta;
	struct ethhdr *eth;
	ssize_t ret;

	/* Adjust meta data */
	meta = (struct reference_meta_data *)(frame_data + sizeof(*eth));
	sequence_counter_to_meta_data(meta, sequence_counter, num_frames_per_cycle);

	/* Send it */
	ret = send(socket_fd, frame_data, frame_length, 0);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "LldpTx: send() for %" PRIu64 " failed: %s\n",
			    sequence_counter, strerror(errno));
		return;
	}

	stat_frame_sent(LLDP_FRAME_TYPE, sequence_counter);
}

static void *lldp_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	unsigned char received_frames[LLDP_TX_FRAME_LENGTH * app_config.lldp_num_frames_per_cycle];
	const bool mirror_enabled = app_config.lldp_rx_mirror_enabled;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	pthread_cond_t *cond = &thread_context->data_cond_var;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	unsigned char *frame;
	int ret, socket_fd;

	socket_fd = thread_context->socket_fd;

	ret = get_interface_mac_address(app_config.lldp_interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "LldpTx: Failed to get Source MAC address!\n");
		return NULL;
	}

	frame = thread_context->tx_frame_data;
	lldp_initialize_frame(frame, source, app_config.lldp_destination);

	while (!thread_context->stop) {
		size_t num_frames, i;

		/*
		 * Wait until signalled. These LLDP frames have to be sent after the DCP
		 * frames. Therefore, the DCP TxThread signals this one here.
		 */
		pthread_mutex_lock(mutex);
		pthread_cond_wait(cond, mutex);
		num_frames = thread_context->num_frames_available;
		thread_context->num_frames_available = 0;
		pthread_mutex_unlock(mutex);

		/*
		 * Send LldpFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			/* Send LldpFrames */
			for (i = 0; i < num_frames; ++i)
				lldp_gen_and_send_frame(frame, app_config.lldp_frame_length,
							app_config.lldp_num_frames_per_cycle,
							socket_fd, sequence_counter++);
		} else {
			size_t len;

			ring_buffer_fetch(thread_context->mirror_buffer, received_frames,
					  sizeof(received_frames), &len);

			/* Len should be a multiple of frame size */
			for (i = 0; i < len / app_config.lldp_frame_length; ++i)
				lldp_send_frame(received_frames + i * app_config.lldp_frame_length,
						app_config.lldp_frame_length,
						app_config.lldp_num_frames_per_cycle, socket_fd);

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

static void *lldp_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const unsigned char *expected_pattern =
		(const unsigned char *)app_config.lldp_payload_pattern;
	const size_t expected_pattern_length = app_config.lldp_payload_pattern_length;
	const size_t num_frames_per_cycle = app_config.lldp_num_frames_per_cycle;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	const bool ignore_rx_errors = app_config.lldp_ignore_rx_errors;
	const bool mirror_enabled = app_config.lldp_rx_mirror_enabled;
	unsigned char frame[LLDP_TX_FRAME_LENGTH], source[ETH_ALEN];
	const ssize_t frame_length = app_config.lldp_frame_length;
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	int socket_fd, ret;

	socket_fd = thread_context->socket_fd;

	ret = get_interface_mac_address(app_config.lldp_interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "LldpRx: Failed to get Source MAC address!\n");
		return NULL;
	}

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "LldpRx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		/* Wait until next period. */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "LldpRx: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		/* Receive Lldp frames. */
		while (true) {
			bool out_of_order, payload_mismatch, frame_id_mismatch;
			struct reference_meta_data *meta;
			uint64_t rx_sequence_counter;
			ssize_t len;

			len = recv(socket_fd, frame, sizeof(frame), 0);
			if (len == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
				log_message(LOG_LEVEL_ERROR, "LldpRx: recv() failed: %s\n",
					    strerror(errno));
				continue;
			}
			if (len == 0)
				continue;

			/* No more frames. Comeback within next period. */
			if (len == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
				break;

			/* Process received frame. */
			if (len != frame_length) {
				log_message(LOG_LEVEL_WARNING,
					    "LldpRx: Frame with wrong length received!\n");
				continue;
			}

			/*
			 * Check cycle counter and payload. The ether type is checked by the
			 * attached BPF filter.
			 */
			meta = (struct reference_meta_data *)(frame + sizeof(struct ethhdr));
			rx_sequence_counter =
				meta_data_to_sequence_counter(meta, num_frames_per_cycle);

			out_of_order = sequence_counter != rx_sequence_counter;
			payload_mismatch =
				memcmp(frame + sizeof(struct ethhdr) + sizeof(rx_sequence_counter),
				       expected_pattern, expected_pattern_length);
			frame_id_mismatch = false;

			stat_frame_received(LLDP_FRAME_TYPE, rx_sequence_counter, out_of_order,
					    payload_mismatch, frame_id_mismatch);

			if (out_of_order) {
				if (!ignore_rx_errors)
					log_message(LOG_LEVEL_WARNING,
						    "LldpRx: frame[%" PRIu64
						    "] SequenceCounter mismatch: %" PRIu64 "!\n",
						    rx_sequence_counter, sequence_counter);
				sequence_counter++;
			}

			if (payload_mismatch)
				log_message(LOG_LEVEL_WARNING,
					    "LldpRx: frame[%" PRIu64
					    "] Payload Pattern mismatch!\n",
					    rx_sequence_counter);

			sequence_counter++;

			/* If mirror enabled, assemble and store the frame for Tx later. */
			if (!mirror_enabled)
				continue;

			/* Build new frame for Tx without VLAN info. */
			lldp_build_frame_from_rx(frame, source);

			/* Store the new frame. */
			ring_buffer_add(thread_context->mirror_buffer, frame, len);

			pthread_mutex_lock(&thread_context->data_mutex);
			thread_context->num_frames_available++;
			pthread_mutex_unlock(&thread_context->data_mutex);
		}
	}

	return NULL;
}

static void *lldp_tx_generation_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	uint64_t num_frames = app_config.lldp_num_frames_per_cycle;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	uint64_t cycle_time_ns = app_config.lldp_burst_period_ns;
	struct timespec wakeup_time;
	int ret;

	/*
	 * The LLDP frames are generated by bursts with a certain period. This thread is responsible
	 * for generating it.
	 */

	ret = get_thread_start_time(0, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "LldpTxGen: Failed to calculate thread start time: %s!\n",
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
			log_message(LOG_LEVEL_ERROR, "LldpTxGen: clock_nanosleep() failed: %s\n",
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

int lldp_threads_create(struct thread_context *thread_context)
{
	int ret;

	if (!CONFIG_IS_TRAFFIC_CLASS_ACTIVE(lldp))
		goto out;

	thread_context->socket_fd = create_lldp_socket();
	if (thread_context->socket_fd < 0) {
		fprintf(stderr, "Failed to create LldpSocket!\n");
		ret = -errno;
		goto err;
	}

	init_mutex(&thread_context->data_mutex);
	init_condition_variable(&thread_context->data_cond_var);

	thread_context->tx_frame_data = calloc(1, LLDP_TX_FRAME_LENGTH);
	if (!thread_context->tx_frame_data) {
		fprintf(stderr, "Failed to allocate Lldp TxFrameData!\n");
		ret = -ENOMEM;
		goto err_tx;
	}

	if (app_config.lldp_rx_mirror_enabled) {
		/* Per period the expectation is: LldpNumFramesPerCycle * MAX_FRAME */
		thread_context->mirror_buffer = ring_buffer_allocate(
			LLDP_TX_FRAME_LENGTH * app_config.lldp_num_frames_per_cycle);
		if (!thread_context->mirror_buffer) {
			fprintf(stderr, "Failed to allocate Lldp Mirror RingBuffer!\n");
			ret = -ENOMEM;
			goto err_buffer;
		}
	}

	ret = create_rt_thread(&thread_context->tx_task_id, "LldpTxThread",
			       app_config.lldp_tx_thread_priority, app_config.lldp_tx_thread_cpu,
			       lldp_tx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Lldp Tx Thread!\n");
		goto err_thread;
	}

	ret = create_rt_thread(&thread_context->tx_gen_task_id, "LldpTxGenThread",
			       app_config.lldp_tx_thread_priority, app_config.lldp_tx_thread_cpu,
			       lldp_tx_generation_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Lldp Tx Thread!\n");
		goto err_thread_txgen;
	}

	ret = create_rt_thread(&thread_context->rx_task_id, "LldpRxThread",
			       app_config.lldp_rx_thread_priority, app_config.lldp_rx_thread_cpu,
			       lldp_rx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Lldp Rx Thread!\n");
		goto err_thread_rx;
	}

out:
	ret = 0;

	return ret;

err_thread_rx:
	thread_context->stop = 1;
	pthread_join(thread_context->tx_gen_task_id, NULL);
err_thread_txgen:
	thread_context->stop = 1;
	pthread_join(thread_context->tx_task_id, NULL);
err_thread:
	ring_buffer_free(thread_context->mirror_buffer);
err_buffer:
	free(thread_context->tx_frame_data);
err_tx:
	close(thread_context->socket_fd);
err:
	return ret;
}

void lldp_threads_free(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	ring_buffer_free(thread_context->mirror_buffer);

	if (thread_context->socket_fd > 0)
		close(thread_context->socket_fd);
}

void lldp_threads_stop(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	thread_context->stop = 1;
	pthread_kill(thread_context->rx_task_id, SIGTERM);

	pthread_join(thread_context->rx_task_id, NULL);
	pthread_join(thread_context->tx_task_id, NULL);
	pthread_join(thread_context->tx_gen_task_id, NULL);
}

void lldp_threads_wait_for_finish(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	pthread_join(thread_context->rx_task_id, NULL);
	pthread_join(thread_context->tx_task_id, NULL);
	pthread_join(thread_context->tx_gen_task_id, NULL);
}
