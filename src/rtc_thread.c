// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
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
#include "rtc_thread.h"
#include "security.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

static void rtc_initialize_frames(unsigned char *frame_data, size_t num_frames,
				  const unsigned char *source, const unsigned char *destination)
{
	size_t i;

	for (i = 0; i < num_frames; ++i)
		initialize_profinet_frame(
			app_config.rtc_security_mode, frame_data + i * RTC_TX_FRAME_LENGTH,
			RTC_TX_FRAME_LENGTH, source, destination, app_config.rtc_payload_pattern,
			app_config.rtc_payload_pattern_length,
			app_config.rtc_vid | RTC_PCP_VALUE << VLAN_PCP_SHIFT, 0x8000);
}

static void rtc_send_frame(const unsigned char *frame_data, size_t frame_length,
			   size_t num_frames_per_cycle, int socket_fd)
{
	struct profinet_secure_header *srt;
	struct vlan_ethernet_header *eth;
	struct profinet_rt_header *rt;
	uint64_t sequence_counter;
	ssize_t ret;

	if (app_config.rtc_security_mode == SECURITY_MODE_NONE) {
		/* Fetch meta data */
		rt = (struct profinet_rt_header *)(frame_data + sizeof(*eth));
		sequence_counter =
			meta_data_to_sequence_counter(&rt->meta_data, num_frames_per_cycle);
	} else {
		/* Fetch meta data */
		srt = (struct profinet_secure_header *)(frame_data + sizeof(*eth));
		sequence_counter =
			meta_data_to_sequence_counter(&srt->meta_data, num_frames_per_cycle);
	}

	/* Send it */
	ret = send(socket_fd, frame_data, frame_length, 0);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: send() for %" PRIu64 " failed: %s\n",
			    sequence_counter, strerror(errno));
		return;
	}

	stat_frame_sent(RTC_FRAME_TYPE, sequence_counter);
}

static void rtc_gen_and_send_frame(struct security_context *security_context,
				   unsigned char *frame_data, size_t frame_length,
				   size_t num_frames_per_cycle, int socket_fd,
				   uint64_t sequence_counter)
{
	uint32_t meta_data_offset = sizeof(struct vlan_ethernet_header) +
				    offsetof(struct profinet_rt_header, meta_data);
	struct prepare_frame_config frame_config;
	ssize_t ret;
	int err;

	frame_config.mode = app_config.rtc_security_mode;
	frame_config.security_context = security_context;
	frame_config.iv_prefix = (const unsigned char *)app_config.rtc_security_iv_prefix;
	frame_config.payload_pattern = frame_data + 1 * RTC_TX_FRAME_LENGTH +
				       sizeof(struct vlan_ethernet_header) +
				       sizeof(struct profinet_secure_header);
	frame_config.payload_pattern_length = frame_length - sizeof(struct vlan_ethernet_header) -
					      sizeof(struct profinet_secure_header) -
					      sizeof(struct security_checksum);
	frame_config.frame_data = frame_data;
	frame_config.frame_length = frame_length;
	frame_config.num_frames_per_cycle = num_frames_per_cycle;
	frame_config.sequence_counter = sequence_counter;
	frame_config.meta_data_offset = meta_data_offset;

	err = prepare_frame_for_tx(&frame_config);
	if (err)
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to prepare frame for Tx!\n");

	/* Send it */
	ret = send(socket_fd, frame_data, frame_length, 0);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: send() for %" PRIu64 " failed: %s\n",
			    sequence_counter, strerror(errno));
		return;
	}

	stat_frame_sent(RTC_FRAME_TYPE, sequence_counter);
}

static void rtc_gen_and_send_xdp_frames(struct security_context *security_context,
					struct xdp_socket *xsk, const unsigned char *tx_frame_data,
					size_t num_frames_per_cycle, uint64_t sequence_counter,
					uint32_t *frame_number)
{
	uint32_t meta_data_offset = sizeof(struct vlan_ethernet_header) +
				    offsetof(struct profinet_rt_header, meta_data);
	struct xdp_gen_config xdp;

	xdp.mode = app_config.rtc_security_mode;
	xdp.security_context = security_context;
	xdp.iv_prefix = (const unsigned char *)app_config.rtc_security_iv_prefix;
	xdp.payload_pattern = tx_frame_data + 1 * RTC_TX_FRAME_LENGTH +
			      sizeof(struct vlan_ethernet_header) +
			      sizeof(struct profinet_secure_header);
	xdp.payload_pattern_length =
		app_config.rtc_frame_length - sizeof(struct vlan_ethernet_header) -
		sizeof(struct profinet_secure_header) - sizeof(struct security_checksum);
	xdp.frame_length = app_config.rtc_frame_length;
	xdp.num_frames_per_cycle = num_frames_per_cycle;
	xdp.frame_number = frame_number;
	xdp.sequence_counter_begin = sequence_counter;
	xdp.meta_data_offset = meta_data_offset;
	xdp.frame_type = RTC_FRAME_TYPE;

	xdp_gen_and_send_frames(xsk, &xdp);
}

static void *rtc_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	unsigned char received_frames[RTC_TX_FRAME_LENGTH * app_config.rtc_num_frames_per_cycle];
	struct security_context *security_context = thread_context->tx_security_context;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	const bool mirror_enabled = app_config.rtc_rx_mirror_enabled;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	int ret, socket_fd;

	socket_fd = thread_context->socket_fd;

	ret = get_interface_mac_address(app_config.rtc_interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to get Source MAC address!\n");
		return NULL;
	}

	rtc_initialize_frames(thread_context->tx_frame_data, 2, source, app_config.rtc_destination);

	prepare_openssl(security_context);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		size_t i;

		if (!thread_context->is_first) {
			/*
			 * Wait until signalled. These RTC frames have to be sent after the TSN Low
			 * frames.
			 */
			pthread_mutex_lock(&thread_context->data_mutex);
			pthread_cond_wait(&thread_context->data_cond_var,
					  &thread_context->data_mutex);
			pthread_mutex_unlock(&thread_context->data_mutex);
		} else {
			/* Wait until next period */
			increment_period(&wakeup_time, cycle_time_ns);

			do {
				ret = clock_nanosleep(app_config.application_clock_id,
						      TIMER_ABSTIME, &wakeup_time, NULL);
			} while (ret == EINTR);

			if (ret) {
				log_message(LOG_LEVEL_ERROR,
					    "RtcTx: clock_nanosleep() failed: %s\n", strerror(ret));
				return NULL;
			}
		}

		/*
		 * Send RtcFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			for (i = 0; i < app_config.rtc_num_frames_per_cycle; ++i)
				rtc_gen_and_send_frame(security_context,
						       thread_context->tx_frame_data,
						       app_config.rtc_frame_length,
						       app_config.rtc_num_frames_per_cycle,
						       socket_fd, sequence_counter++);
		} else {
			size_t len;

			ring_buffer_fetch(thread_context->mirror_buffer, received_frames,
					  sizeof(received_frames), &len);

			/* Len should be a multiple of frame size */
			for (i = 0; i < len / app_config.rtc_frame_length; ++i)
				rtc_send_frame(received_frames + i * app_config.rtc_frame_length,
					       app_config.rtc_frame_length,
					       app_config.rtc_num_frames_per_cycle, socket_fd);
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

/*
 * This Tx thread routine differs to the standard one in terms of the sending interface. This one
 * uses the AF_XDP user space interface.
 */
static void *rtc_xdp_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	struct security_context *security_context = thread_context->tx_security_context;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	const bool mirror_enabled = app_config.rtc_rx_mirror_enabled;
	uint32_t frame_number = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	const size_t num_frames = app_config.rtc_num_frames_per_cycle;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	unsigned char *frame_data;
	struct xdp_socket *xsk;
	int ret;

	xsk = thread_context->xsk;

	ret = get_interface_mac_address(app_config.rtc_interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to get Source MAC address!\n");
		return NULL;
	}

	/* First half of umem area is for Rx, the second half is for Tx. */
	frame_data = xsk_umem__get_data(xsk->umem.buffer,
					XDP_FRAME_SIZE * XSK_RING_PROD__DEFAULT_NUM_DESCS);

	/* Initialize all Tx frames */
	rtc_initialize_frames(frame_data, XSK_RING_CONS__DEFAULT_NUM_DESCS, source,
			      app_config.rtc_destination);
	rtc_initialize_frames(thread_context->tx_frame_data, 2, source, app_config.rtc_destination);

	prepare_openssl(security_context);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		if (!thread_context->is_first) {
			/*
			 * Wait until signalled. These RTC frames have to be sent after the TSN Low
			 * frames.
			 */
			pthread_mutex_lock(&thread_context->data_mutex);
			pthread_cond_wait(&thread_context->data_cond_var,
					  &thread_context->data_mutex);
			pthread_mutex_unlock(&thread_context->data_mutex);
		} else {
			/* Wait until next period */
			increment_period(&wakeup_time, cycle_time_ns);

			do {
				ret = clock_nanosleep(app_config.application_clock_id,
						      TIMER_ABSTIME, &wakeup_time, NULL);
			} while (ret == EINTR);

			if (ret) {
				log_message(LOG_LEVEL_ERROR,
					    "RtcTx: clock_nanosleep() failed: %s\n", strerror(ret));
				return NULL;
			}
		}

		/*
		 * Send RtcFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			rtc_gen_and_send_xdp_frames(security_context, xsk,
						    thread_context->tx_frame_data, num_frames,
						    sequence_counter, &frame_number);
			sequence_counter += num_frames;
		} else {
			unsigned int received;
			uint64_t i;

			pthread_mutex_lock(&thread_context->xdp_data_mutex);

			received = thread_context->received_frames;

			sequence_counter = thread_context->rx_sequence_counter - received;

			/*
			 * The XDP receiver stored the frames within the umem area and populated the
			 * Tx ring. Now, the Tx ring can be committed to the kernel. Furthermore,
			 * already transmitted frames from last cycle can be recycled for Rx.
			 */

			xsk_ring_prod__submit(&xsk->tx, received);

			for (i = sequence_counter; i < sequence_counter + received; ++i)
				stat_frame_sent(RTC_FRAME_TYPE, i);

			xsk->outstanding_tx += received;
			thread_context->received_frames = 0;
			xdp_complete_tx(xsk);

			pthread_mutex_unlock(&thread_context->xdp_data_mutex);
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

static int rtc_rx_frame(void *data, unsigned char *frame_data, size_t len)
{
	struct thread_context *thread_context = data;
	const unsigned char *expected_pattern =
		(const unsigned char *)app_config.rtc_payload_pattern;
	struct security_context *security_context = thread_context->rx_security_context;
	const size_t expected_pattern_length = app_config.rtc_payload_pattern_length;
	const size_t num_frames_per_cycle = app_config.rtc_num_frames_per_cycle;
	const bool mirror_enabled = app_config.rtc_rx_mirror_enabled;
	const bool ignore_rx_errors = app_config.rtc_ignore_rx_errors;
	size_t expected_frame_length = app_config.rtc_frame_length;
	bool out_of_order, payload_mismatch, frame_id_mismatch;
	unsigned char plaintext[RTC_TX_FRAME_LENGTH];
	unsigned char new_frame[RTC_TX_FRAME_LENGTH];
	struct profinet_secure_header *srt;
	struct profinet_rt_header *rt;
	uint64_t sequence_counter;
	bool vlan_tag_missing;
	void *p = frame_data;
	struct ethhdr *eth;
	uint16_t frame_id;
	uint16_t proto;

	if (len < sizeof(struct vlan_ethernet_header)) {
		log_message(LOG_LEVEL_WARNING, "RtcRx: Too small frame received!\n");
		return -EINVAL;
	}

	eth = p;
	if (eth->h_proto == htons(ETH_P_8021Q)) {
		struct vlan_ethernet_header *veth = p;

		proto = veth->vlan_encapsulated_proto;
		p += sizeof(*veth);
		vlan_tag_missing = false;
	} else {
		proto = eth->h_proto;
		p += sizeof(*eth);
		expected_frame_length -= sizeof(struct vlan_header);
		vlan_tag_missing = true;
	}

	if (proto != htons(ETH_P_PROFINET_RT)) {
		log_message(LOG_LEVEL_WARNING, "RtcRx: Not a Profinet frame received!\n");
		return -EINVAL;
	}

	/* Check frame length: VLAN tag might be stripped or not. Check it. */
	if (len != expected_frame_length) {
		log_message(LOG_LEVEL_WARNING, "RtcRx: Frame with wrong length received!\n");
		return -EINVAL;
	}

	/* Check cycle counter, frame id range and payload. */
	if (app_config.rtc_security_mode == SECURITY_MODE_NONE) {
		rt = p;
		p += sizeof(*rt);

		frame_id = be16toh(rt->frame_id);
		sequence_counter =
			meta_data_to_sequence_counter(&rt->meta_data, num_frames_per_cycle);
	} else if (app_config.rtc_security_mode == SECURITY_MODE_AO) {
		unsigned char *begin_of_security_checksum;
		unsigned char *begin_of_aad_data;
		size_t size_of_eth_header;
		size_t size_of_aad_data;
		struct security_iv iv;
		int ret;

		srt = p;
		p += sizeof(*srt);

		frame_id = be16toh(srt->frame_id);
		sequence_counter =
			meta_data_to_sequence_counter(&srt->meta_data, num_frames_per_cycle);

		/* Authenticate received Profinet Frame */
		size_of_eth_header = vlan_tag_missing ? sizeof(struct ethhdr)
						      : sizeof(struct vlan_ethernet_header);

		begin_of_aad_data = frame_data + size_of_eth_header;
		size_of_aad_data = len - size_of_eth_header - sizeof(struct security_checksum);
		begin_of_security_checksum = frame_data + (len - sizeof(struct security_checksum));

		prepare_iv((const unsigned char *)app_config.rtc_security_iv_prefix,
			   sequence_counter, &iv);

		ret = security_decrypt(security_context, NULL, 0, begin_of_aad_data,
				       size_of_aad_data, begin_of_security_checksum,
				       (unsigned char *)&iv, NULL);
		if (ret)
			log_message(LOG_LEVEL_WARNING,
				    "RtcRx: frame[%" PRIu64 "] Not authentificated\n",
				    sequence_counter);
	} else {
		unsigned char *begin_of_security_checksum;
		unsigned char *begin_of_ciphertext;
		unsigned char *begin_of_aad_data;
		size_t size_of_ciphertext;
		size_t size_of_eth_header;
		size_t size_of_aad_data;
		struct security_iv iv;
		int ret;

		srt = p;

		frame_id = be16toh(srt->frame_id);
		sequence_counter =
			meta_data_to_sequence_counter(&srt->meta_data, num_frames_per_cycle);

		/* Authenticate received Profinet Frame */
		size_of_eth_header = vlan_tag_missing ? sizeof(struct ethhdr)
						      : sizeof(struct vlan_ethernet_header);

		begin_of_aad_data = frame_data + size_of_eth_header;
		size_of_aad_data = sizeof(*srt);
		begin_of_security_checksum = frame_data + (len - sizeof(struct security_checksum));
		begin_of_ciphertext = frame_data + size_of_eth_header + sizeof(*srt);
		size_of_ciphertext = len - sizeof(struct vlan_ethernet_header) -
				     sizeof(struct profinet_secure_header) -
				     sizeof(struct security_checksum);

		prepare_iv((const unsigned char *)app_config.rtc_security_iv_prefix,
			   sequence_counter, &iv);

		ret = security_decrypt(security_context, begin_of_ciphertext, size_of_ciphertext,
				       begin_of_aad_data, size_of_aad_data,
				       begin_of_security_checksum, (unsigned char *)&iv, plaintext);
		if (ret)
			log_message(LOG_LEVEL_WARNING,
				    "RtcRx: frame[%" PRIu64 "] Not authentificated and decrypted\n",
				    sequence_counter);

		/* plaintext points to the decrypted payload */
		p = plaintext;
	}

	out_of_order = sequence_counter != thread_context->rx_sequence_counter;
	payload_mismatch = memcmp(p, expected_pattern, expected_pattern_length);
	frame_id_mismatch = frame_id != 0x8000;

	stat_frame_received(RTC_FRAME_TYPE, sequence_counter, out_of_order, payload_mismatch,
			    frame_id_mismatch);

	if (frame_id_mismatch)
		log_message(LOG_LEVEL_WARNING,
			    "RtcRx: frame[%" PRIu64 "] FrameId mismatch: 0x%4x!\n",
			    sequence_counter, 0x8000);

	if (out_of_order) {
		if (!ignore_rx_errors)
			log_message(LOG_LEVEL_WARNING,
				    "RtcRx: frame[%" PRIu64 "] SequenceCounter mismatch: %" PRIu64
				    "!\n",
				    sequence_counter, thread_context->rx_sequence_counter);
		thread_context->rx_sequence_counter++;
	}

	if (payload_mismatch)
		log_message(LOG_LEVEL_WARNING,
			    "RtcRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n",
			    sequence_counter);

	thread_context->rx_sequence_counter++;

	/*
	 * If mirror enabled, assemble and store the frame for Tx later.
	 *
	 * In case of XDP the Rx umem area will be reused for Tx.
	 */
	if (!mirror_enabled)
		return 0;

	if (app_config.rtc_xdp_enabled) {
		/* Re-add vlan tag */
		if (vlan_tag_missing)
			insert_vlan_tag(frame_data, len,
					app_config.rtc_vid | RTC_PCP_VALUE << VLAN_PCP_SHIFT);

		/* Swap mac addresses inline */
		swap_mac_addresses(frame_data, len);
	} else {
		/* Build new frame for Tx with VLAN info. */
		build_vlan_frame_from_rx(frame_data, len, new_frame, sizeof(new_frame),
					 ETH_P_PROFINET_RT,
					 app_config.rtc_vid | RTC_PCP_VALUE << VLAN_PCP_SHIFT);

		/* Store the new frame. */
		ring_buffer_add(thread_context->mirror_buffer, new_frame,
				len + sizeof(struct vlan_header));
	}

	return 0;
}

static void *rtc_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	unsigned char frame[RTC_TX_FRAME_LENGTH];
	int socket_fd;

	socket_fd = thread_context->socket_fd;

	prepare_openssl(thread_context->rx_security_context);

	while (!thread_context->stop) {
		ssize_t len;

		/* Wait for RTC frame */
		len = recv(socket_fd, frame, sizeof(frame), 0);
		if (len < 0) {
			log_message(LOG_LEVEL_ERROR, "RtcRx: recv() failed: %s\n", strerror(errno));
			return NULL;
		}
		if (len == 0)
			return NULL;

		rtc_rx_frame(thread_context, frame, len);
	}

	return NULL;
}

static void *rtc_xdp_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const long long cycle_time_ns = app_config.application_base_cycle_time_ns;
	const bool mirror_enabled = app_config.rtc_rx_mirror_enabled;
	const size_t frame_length = app_config.rtc_frame_length;
	struct xdp_socket *xsk = thread_context->xsk;
	struct timespec wakeup_time;
	int ret;

	prepare_openssl(thread_context->rx_security_context);

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "RtcRx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		unsigned int received;

		/* Wait until next period */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "RtcRx: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		pthread_mutex_lock(&thread_context->xdp_data_mutex);
		received = xdp_receive_frames(xsk, frame_length, mirror_enabled, rtc_rx_frame,
					      thread_context);
		thread_context->received_frames = received;
		pthread_mutex_unlock(&thread_context->xdp_data_mutex);
	}

	return NULL;
}

int rtc_threads_create(struct thread_context *thread_context)
{
	int ret;

	if (!CONFIG_IS_TRAFFIC_CLASS_ACTIVE(rtc))
		goto out;

	init_mutex(&thread_context->data_mutex);
	init_condition_variable(&thread_context->data_cond_var);

	thread_context->tx_frame_data = calloc(2, RTC_TX_FRAME_LENGTH);
	if (!thread_context->tx_frame_data) {
		fprintf(stderr, "Failed to allocate RtcTxFrameData\n");
		ret = -ENOMEM;
		goto err_tx;
	}

	/* For XDP a AF_XDP socket is allocated. Otherwise a Linux raw socket is used. */
	if (app_config.rtc_xdp_enabled) {
		thread_context->socket_fd = 0;
		thread_context->xsk = xdp_open_socket(
			app_config.rtc_interface, app_config.application_xdp_program,
			app_config.rtc_rx_queue, app_config.rtc_xdp_skb_mode,
			app_config.rtc_xdp_zc_mode, app_config.rtc_xdp_wakeup_mode,
			app_config.rtc_xdp_busy_poll_mode);
		if (!thread_context->xsk) {
			fprintf(stderr, "Failed to create Rtc Xdp socket!\n");
			ret = -ENOMEM;
			goto err_socket;
		}
	} else {
		thread_context->xsk = NULL;
		thread_context->socket_fd = create_rtc_socket();
		if (thread_context->socket_fd < 0) {
			fprintf(stderr, "Failed to create RtcSocket!\n");
			ret = -errno;
			goto err_socket;
		}
	}

	/* Same as above. For XDP the umem area is used. */
	if (app_config.rtc_rx_mirror_enabled && !app_config.rtc_xdp_enabled) {
		/* Per period the expectation is: RtcNumFramesPerCycle * MAX_FRAME */
		thread_context->mirror_buffer = ring_buffer_allocate(
			RTC_TX_FRAME_LENGTH * app_config.rtc_num_frames_per_cycle);
		if (!thread_context->mirror_buffer) {
			fprintf(stderr, "Failed to allocate Rtc Mirror RingBuffer!\n");
			ret = -ENOMEM;
			goto err_thread;
		}
	}

	if (app_config.rtc_security_mode != SECURITY_MODE_NONE) {
		thread_context->tx_security_context =
			security_init(app_config.rtc_security_algorithm,
				      (unsigned char *)app_config.rtc_security_key);
		if (!thread_context->tx_security_context) {
			fprintf(stderr, "Failed to initialize Tx security context!\n");
			ret = -ENOMEM;
			goto err_tx_sec;
		}

		thread_context->rx_security_context =
			security_init(app_config.rtc_security_algorithm,
				      (unsigned char *)app_config.rtc_security_key);
		if (!thread_context->rx_security_context) {
			fprintf(stderr, "Failed to initialize Rx security context!\n");
			ret = -ENOMEM;
			goto err_rx_sec;
		}
	} else {
		thread_context->tx_security_context = NULL;
		thread_context->rx_security_context = NULL;
	}

	ret = create_rt_thread(&thread_context->tx_task_id, "RtcTxThread",
			       app_config.rtc_tx_thread_priority, app_config.rtc_tx_thread_cpu,
			       app_config.rtc_xdp_enabled ? rtc_xdp_tx_thread_routine
							  : rtc_tx_thread_routine,
			       thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Rtc Tx thread!\n");
		goto err_thread_create1;
	}

	ret = create_rt_thread(&thread_context->rx_task_id, "RtcRxThread",
			       app_config.rtc_rx_thread_priority, app_config.rtc_rx_thread_cpu,
			       app_config.rtc_xdp_enabled ? rtc_xdp_rx_thread_routine
							  : rtc_rx_thread_routine,
			       thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Rtc Rx thread!\n");
		goto err_thread_create2;
	}

out:
	return 0;

err_thread_create2:
	thread_context->stop = 1;
	pthread_join(thread_context->tx_task_id, NULL);
err_thread_create1:
	security_exit(thread_context->rx_security_context);
err_rx_sec:
	security_exit(thread_context->tx_security_context);
err_tx_sec:
	ring_buffer_free(thread_context->mirror_buffer);
err_thread:
	if (thread_context->socket_fd)
		close(thread_context->socket_fd);
	if (thread_context->xsk)
		xdp_close_socket(thread_context->xsk, app_config.rtc_interface,
				 app_config.rtc_xdp_skb_mode);
err_socket:
	free(thread_context->tx_frame_data);
err_tx:
	return ret;
}

void rtc_threads_free(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	security_exit(thread_context->tx_security_context);
	security_exit(thread_context->rx_security_context);

	ring_buffer_free(thread_context->mirror_buffer);

	free(thread_context->tx_frame_data);

	if (thread_context->socket_fd > 0)
		close(thread_context->socket_fd);

	if (thread_context->xsk)
		xdp_close_socket(thread_context->xsk, app_config.rtc_interface,
				 app_config.rtc_xdp_skb_mode);
}

void rtc_threads_stop(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	thread_context->stop = 1;

	pthread_kill(thread_context->rx_task_id, SIGTERM);

	pthread_join(thread_context->rx_task_id, NULL);
	pthread_join(thread_context->tx_task_id, NULL);
}

void rtc_threads_wait_for_finish(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	pthread_join(thread_context->rx_task_id, NULL);
	pthread_join(thread_context->tx_task_id, NULL);
}
