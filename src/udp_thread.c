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
#include "log.h"
#include "net.h"
#include "net_def.h"
#include "stat.h"
#include "thread.h"
#include "udp_thread.h"
#include "utils.h"

static void udp_initialize_frame(const struct udp_thread_configuration *udp_config,
				 unsigned char *frame_data)
{
	struct reference_meta_data *meta;

	/*
	 * UdpFrame:
	 *   Cycle counter
	 *   Payload
	 *   Padding to maxFrame
	 */

	/* Payload: SequenceCounter + Data */
	meta = (struct reference_meta_data *)frame_data;
	memset(meta, '\0', sizeof(*meta));
	memcpy(frame_data + sizeof(*meta), udp_config->udp_payload_pattern,
	       udp_config->udp_payload_pattern_length);

	/* Padding: '\0' */
}

static void udp_send_frame(const struct udp_thread_configuration *udp_config,
			   const unsigned char *frame_data, size_t frame_length,
			   size_t num_frames_per_cycle, int socket_fd,
			   const struct sockaddr_storage *destination)
{
	struct reference_meta_data *meta;
	uint64_t sequence_counter;
	ssize_t ret = -1;

	/* Fetch meta data */
	meta = (struct reference_meta_data *)frame_data;
	sequence_counter = meta_data_to_sequence_counter(meta, num_frames_per_cycle);

	/* Send it */
	switch (destination->ss_family) {
	case AF_INET:
		ret = sendto(socket_fd, frame_data, frame_length, 0,
			     (struct sockaddr_in *)destination, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		ret = sendto(socket_fd, frame_data, frame_length, 0,
			     (struct sockaddr_in6 *)destination, sizeof(struct sockaddr_in6));
		break;
	}
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "Udp%sTx: send() for %" PRIu64 " failed: %s\n",
			    udp_config->udp_suffix, sequence_counter, strerror(errno));
		return;
	}

	stat_frame_sent(udp_config->frame_type, sequence_counter);
}

static void udp_gen_and_send_frame(const struct udp_thread_configuration *udp_config,
				   unsigned char *frame_data, size_t frame_length,
				   size_t num_frames_per_cycle, int socket_fd,
				   uint64_t sequence_counter,
				   const struct sockaddr_storage *destination)
{
	struct reference_meta_data *meta;
	ssize_t ret = -1;

	/* Adjust meta data */
	meta = (struct reference_meta_data *)frame_data;
	sequence_counter_to_meta_data(meta, sequence_counter, num_frames_per_cycle);

	/* Send it */
	switch (destination->ss_family) {
	case AF_INET:
		ret = sendto(socket_fd, frame_data, frame_length, 0,
			     (struct sockaddr_in *)destination, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		ret = sendto(socket_fd, frame_data, frame_length, 0,
			     (struct sockaddr_in6 *)destination, sizeof(struct sockaddr_in6));
		break;
	default:
		ret = -EINVAL;
	}
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "Udp%sTx: send() for %" PRIu64 " failed: %s\n",
			    udp_config->udp_suffix, sequence_counter, strerror(errno));
		return;
	}

	stat_frame_sent(udp_config->frame_type, sequence_counter);
}

static void *udp_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct udp_thread_configuration *udp_config = thread_context->private_data;
	unsigned char received_frames[MAX_FRAME_SIZE * udp_config->udp_num_frames_per_cycle];
	const bool mirror_enabled = udp_config->udp_rx_mirror_enabled;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	pthread_cond_t *cond = &thread_context->data_cond_var;
	uint64_t sequence_counter = 0;
	unsigned char *frame;
	int socket_fd;

	socket_fd = thread_context->socket_fd;
	frame = thread_context->tx_frame_data;

	udp_initialize_frame(udp_config, frame);

	while (!thread_context->stop) {
		size_t num_frames, i;

		/*
		 * Wait until signalled. These UDP frames have to be sent after the LLDP
		 * frames. Therefore, the LLDP or UDP High TxThread signals this one here.
		 */
		pthread_mutex_lock(mutex);
		pthread_cond_wait(cond, mutex);
		num_frames = thread_context->num_frames_available;
		thread_context->num_frames_available = 0;
		pthread_mutex_unlock(mutex);

		/*
		 * Send UdpFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			/* Send UdpFrames */
			for (i = 0; i < num_frames; ++i)
				udp_gen_and_send_frame(
					udp_config, frame, udp_config->udp_frame_length,
					udp_config->udp_num_frames_per_cycle, socket_fd,
					sequence_counter++, &thread_context->destination);
		} else {
			size_t len;

			ring_buffer_fetch(thread_context->mirror_buffer, received_frames,
					  sizeof(received_frames), &len);

			/* Len should be a multiple of frame size */
			for (i = 0; i < len / udp_config->udp_frame_length; ++i)
				udp_send_frame(udp_config,
					       received_frames + i * udp_config->udp_frame_length,
					       udp_config->udp_frame_length,
					       udp_config->udp_num_frames_per_cycle, socket_fd,
					       &thread_context->destination);

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

static void *udp_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct udp_thread_configuration *udp_config = thread_context->private_data;
	const unsigned char *expected_pattern =
		(const unsigned char *)udp_config->udp_payload_pattern;
	const size_t expected_pattern_length = udp_config->udp_payload_pattern_length;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	const size_t num_frames_per_cycle = udp_config->udp_num_frames_per_cycle;
	const bool mirror_enabled = udp_config->udp_rx_mirror_enabled;
	const bool ignore_rx_errors = udp_config->udp_ignore_rx_errors;
	const ssize_t frame_length = udp_config->udp_frame_length;
	unsigned char frame[MAX_FRAME_SIZE];
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	int socket_fd, ret;

	socket_fd = thread_context->socket_fd;

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "Udp%sRx: Failed to calculate thread start time: %s!\n",
			    udp_config->udp_suffix, strerror(errno));
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
			log_message(LOG_LEVEL_ERROR, "Udp%sRx: clock_nanosleep() failed: %s\n",
				    udp_config->udp_suffix, strerror(ret));
			return NULL;
		}

		/* Receive Udp packets. */
		while (true) {
			bool out_of_order, payload_mismatch, frame_id_mismatch;
			struct reference_meta_data *meta;
			uint64_t rx_sequence_counter;
			ssize_t len;

			len = recv(socket_fd, frame, sizeof(frame), 0);
			if (len == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
				log_message(LOG_LEVEL_ERROR, "Udp%sRx: recv() failed: %s\n",
					    udp_config->udp_suffix, strerror(errno));
				continue;
			}
			if (len == 0)
				continue;

			/* No more frames. Comeback within next period. */
			if (len == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
				break;

			/* Process received packet. */
			if (len != frame_length) {
				log_message(LOG_LEVEL_WARNING,
					    "Udp%sRx: Frame with wrong length received!\n",
					    udp_config->udp_suffix);
				continue;
			}

			/*
			 * Check cycle counter and payload. The ether type is checked by the
			 * attached BPF filter.
			 */
			meta = (struct reference_meta_data *)frame;
			rx_sequence_counter =
				meta_data_to_sequence_counter(meta, num_frames_per_cycle);

			out_of_order = sequence_counter != rx_sequence_counter;
			payload_mismatch = memcmp(frame + sizeof(struct reference_meta_data),
						  expected_pattern, expected_pattern_length);
			frame_id_mismatch = false;

			stat_frame_received(udp_config->frame_type, sequence_counter, out_of_order,
					    payload_mismatch, frame_id_mismatch);

			if (out_of_order) {
				if (!ignore_rx_errors)
					log_message(LOG_LEVEL_WARNING,
						    "Udp%sRx: frame[%" PRIu64
						    "] SequenceCounter mismatch: %" PRIu64 "!\n",
						    udp_config->udp_suffix, rx_sequence_counter,
						    sequence_counter);
				sequence_counter++;
			}

			sequence_counter++;

			if (payload_mismatch)
				log_message(LOG_LEVEL_WARNING,
					    "Udp%sRx: frame[%" PRIu64
					    "] Payload Pattern mismatch!\n",
					    udp_config->udp_suffix, rx_sequence_counter);

			/* If mirror enabled, assemble and store the frame for Tx later. */
			if (!mirror_enabled)
				continue;

			/* Store the new frame. */
			ring_buffer_add(thread_context->mirror_buffer, frame, len);

			pthread_mutex_lock(&thread_context->data_mutex);
			thread_context->num_frames_available++;
			pthread_mutex_unlock(&thread_context->data_mutex);
		}
	}

	return NULL;
}

static void *udp_tx_generation_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct udp_thread_configuration *udp_config = thread_context->private_data;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	uint64_t cycle_time_ns = udp_config->udp_burst_period_ns;
	uint64_t num_frames = udp_config->udp_num_frames_per_cycle;
	struct timespec wakeup_time;
	int ret;

	/*
	 * The UDP frames are generated by bursts with a certain period. This thread is responsible
	 * for generating it.
	 */

	ret = get_thread_start_time(0, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "Udp%sTxGen: Failed to calculate thread start time: %s!\n",
			    udp_config->udp_suffix, strerror(errno));
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
			log_message(LOG_LEVEL_ERROR, "Udp%sTxGen: clock_nanosleep() failed: %s\n",
				    udp_config->udp_suffix, strerror(ret));
			return NULL;
		}

		/* Generate frames */
		pthread_mutex_lock(mutex);
		thread_context->num_frames_available = num_frames;
		pthread_mutex_unlock(mutex);
	}

	return NULL;
}

static int udp_threads_create(struct thread_context *thread_context,
			      struct udp_thread_configuration *udp_thread_config)
{
	char thread_name[128];
	int ret;

	if (!strcmp(udp_thread_config->udp_suffix, "High") &&
	    !CONFIG_IS_TRAFFIC_CLASS_ACTIVE(udp_high)) {
		ret = 0;
		goto out;
	}
	if (!strcmp(udp_thread_config->udp_suffix, "Low") &&
	    !CONFIG_IS_TRAFFIC_CLASS_ACTIVE(udp_low)) {
		ret = 0;
		goto out;
	}

	thread_context->private_data = udp_thread_config;
	thread_context->socket_fd = create_udp_socket(
		udp_thread_config->udp_destination, udp_thread_config->udp_source,
		udp_thread_config->udp_port, udp_thread_config->udp_socket_priority,
		&thread_context->destination);
	if (thread_context->socket_fd < 0) {
		fprintf(stderr, "Failed to create UdpSocket!\n");
		ret = -errno;
		goto err;
	}

	init_mutex(&thread_context->data_mutex);
	init_condition_variable(&thread_context->data_cond_var);

	thread_context->tx_frame_data = calloc(1, MAX_FRAME_SIZE);
	if (!thread_context->tx_frame_data) {
		fprintf(stderr, "Failed to allocate Udp TxFrameData!\n");
		ret = -ENOMEM;
		goto err_tx;
	}

	if (udp_thread_config->udp_rx_mirror_enabled) {
		/* Per period the expectation is: UdpNumFramesPerCycle * MAX_FRAME */
		thread_context->mirror_buffer = ring_buffer_allocate(
			MAX_FRAME_SIZE * udp_thread_config->udp_num_frames_per_cycle);
		if (!thread_context->mirror_buffer) {
			fprintf(stderr, "Failed to allocate Udp Mirror RingBuffer!\n");
			ret = -ENOMEM;
			goto err_buffer;
		}
	}

	snprintf(thread_name, sizeof(thread_name), "Udp%sTxThread", udp_thread_config->udp_suffix);

	ret = create_rt_thread(
		&thread_context->tx_task_id, thread_name, udp_thread_config->udp_tx_thread_priority,
		udp_thread_config->udp_tx_thread_cpu, udp_tx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Udp Tx Thread!\n");
		goto err_thread;
	}

	snprintf(thread_name, sizeof(thread_name), "Udp%sTxGenThread",
		 udp_thread_config->udp_suffix);

	ret = create_rt_thread(&thread_context->tx_gen_task_id, "UdpLowTxGenThread",
			       udp_thread_config->udp_tx_thread_priority,
			       udp_thread_config->udp_tx_thread_cpu,
			       udp_tx_generation_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Udp TxGen Thread!\n");
		goto err_thread_txgen;
	}

	snprintf(thread_name, sizeof(thread_name), "Udp%sRxThread", udp_thread_config->udp_suffix);

	ret = create_rt_thread(
		&thread_context->rx_task_id, thread_name, udp_thread_config->udp_rx_thread_priority,
		udp_thread_config->udp_rx_thread_cpu, udp_rx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Udp Rx Thread!\n");
		goto err_thread_rx;
	}

	return 0;

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
out:
	free(udp_thread_config);
	return ret;
}

static void udp_threads_free(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	ring_buffer_free(thread_context->mirror_buffer);

	if (thread_context->socket_fd > 0)
		close(thread_context->socket_fd);

	free((void *)thread_context->private_data);
}

static void udp_threads_stop(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	thread_context->stop = 1;

	pthread_kill(thread_context->rx_task_id, SIGTERM);

	pthread_join(thread_context->rx_task_id, NULL);
	pthread_join(thread_context->tx_task_id, NULL);
	pthread_join(thread_context->tx_gen_task_id, NULL);
}

static void udp_threads_wait_for_finish(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	pthread_join(thread_context->rx_task_id, NULL);
	pthread_join(thread_context->tx_task_id, NULL);
	pthread_join(thread_context->tx_gen_task_id, NULL);
}

int udp_low_threads_create(struct thread_context *udp_thread_context)
{
	struct udp_thread_configuration *udp_config;

	udp_config = calloc(1, sizeof(*udp_config));
	if (!udp_config)
		return -ENOMEM;

	udp_config->frame_type = UDP_LOW_FRAME_TYPE;
	udp_config->udp_suffix = "Low";
	udp_config->udp_rx_mirror_enabled = app_config.udp_low_rx_mirror_enabled;
	udp_config->udp_ignore_rx_errors = app_config.udp_low_ignore_rx_errors;
	udp_config->udp_burst_period_ns = app_config.udp_low_burst_period_ns;
	udp_config->udp_num_frames_per_cycle = app_config.udp_low_num_frames_per_cycle;
	udp_config->udp_payload_pattern = app_config.udp_low_payload_pattern;
	udp_config->udp_payload_pattern_length = app_config.udp_low_payload_pattern_length;
	udp_config->udp_frame_length = app_config.udp_low_frame_length;
	udp_config->udp_socket_priority = app_config.udp_low_socket_priority;
	udp_config->udp_tx_thread_priority = app_config.udp_low_tx_thread_priority;
	udp_config->udp_rx_thread_priority = app_config.udp_low_rx_thread_priority;
	udp_config->udp_tx_thread_cpu = app_config.udp_low_tx_thread_cpu;
	udp_config->udp_rx_thread_cpu = app_config.udp_low_rx_thread_cpu;
	udp_config->udp_port = app_config.udp_low_port;
	udp_config->udp_destination = app_config.udp_low_destination;
	udp_config->udp_source = app_config.udp_low_source;

	return udp_threads_create(udp_thread_context, udp_config);
}

void udp_low_threads_stop(struct thread_context *thread_context)
{
	udp_threads_stop(thread_context);
}

void udp_low_threads_free(struct thread_context *thread_context)
{
	udp_threads_free(thread_context);
}

void udp_low_threads_wait_for_finish(struct thread_context *thread_context)
{
	udp_threads_wait_for_finish(thread_context);
}

int udp_high_threads_create(struct thread_context *udp_thread_context)
{
	struct udp_thread_configuration *udp_config;

	udp_config = calloc(1, sizeof(*udp_config));
	if (!udp_config)
		return -ENOMEM;

	udp_config->frame_type = UDP_HIGH_FRAME_TYPE;
	udp_config->udp_suffix = "High";
	udp_config->udp_rx_mirror_enabled = app_config.udp_high_rx_mirror_enabled;
	udp_config->udp_ignore_rx_errors = app_config.udp_high_ignore_rx_errors;
	udp_config->udp_burst_period_ns = app_config.udp_high_burst_period_ns;
	udp_config->udp_num_frames_per_cycle = app_config.udp_high_num_frames_per_cycle;
	udp_config->udp_payload_pattern = app_config.udp_high_payload_pattern;
	udp_config->udp_payload_pattern_length = app_config.udp_high_payload_pattern_length;
	udp_config->udp_frame_length = app_config.udp_high_frame_length;
	udp_config->udp_socket_priority = app_config.udp_high_socket_priority;
	udp_config->udp_tx_thread_priority = app_config.udp_high_tx_thread_priority;
	udp_config->udp_rx_thread_priority = app_config.udp_high_rx_thread_priority;
	udp_config->udp_tx_thread_cpu = app_config.udp_high_tx_thread_cpu;
	udp_config->udp_rx_thread_cpu = app_config.udp_high_rx_thread_cpu;
	udp_config->udp_port = app_config.udp_high_port;
	udp_config->udp_destination = app_config.udp_high_destination;
	udp_config->udp_source = app_config.udp_high_source;

	return udp_threads_create(udp_thread_context, udp_config);
}

void udp_high_threads_free(struct thread_context *thread_context)
{
	udp_threads_free(thread_context);
}

void udp_high_threads_stop(struct thread_context *thread_context)
{
	udp_threads_stop(thread_context);
}

void udp_high_threads_wait_for_finish(struct thread_context *thread_context)
{
	udp_threads_wait_for_finish(thread_context);
}
