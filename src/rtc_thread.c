// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
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
#include <linux/if_packet.h>
#include <linux/if_vlan.h>

#include "config.h"
#include "log.h"
#include "net.h"
#include "packet.h"
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
			app_config.rtc_security_mode, frame_idx(frame_data, i), MAX_FRAME_SIZE,
			source, destination, app_config.rtc_payload_pattern,
			app_config.rtc_payload_pattern_length,
			app_config.rtc_vid | app_config.rtc_pcp << VLAN_PCP_SHIFT, RTC_FRAMEID);
}

static int rtc_send_messages(struct thread_context *thread_context, int socket_fd,
			     struct sockaddr_ll *destination, unsigned char *frame_data,
			     size_t num_frames)
{
	struct packet_send_request send_req = {
		.traffic_class = stat_frame_type_to_string(RTC_FRAME_TYPE),
		.socket_fd = socket_fd,
		.destination = destination,
		.frame_data = frame_data,
		.num_frames = num_frames,
		.frame_length = app_config.rtc_frame_length,
		.wakeup_time = 0,
		.duration = 0,
		.tx_time_offset = 0,
		.meta_data_offset = thread_context->meta_data_offset,
		.mirror_enabled = app_config.rtc_rx_mirror_enabled,
		.tx_time_enabled = false,
	};

	return packet_send_messages(thread_context->packet_context, &send_req);
}

static int rtc_send_frames(struct thread_context *thread_context, unsigned char *frame_data,
			   size_t num_frames, int socket_fd, struct sockaddr_ll *destination)
{
	int len, i;

	/* Send it */
	len = rtc_send_messages(thread_context, socket_fd, destination, frame_data, num_frames);

	for (i = 0; i < len; i++) {
		uint64_t sequence_counter;

		sequence_counter = get_sequence_counter(
			frame_data + i * app_config.rtc_frame_length,
			thread_context->meta_data_offset, app_config.rtc_num_frames_per_cycle);

		stat_frame_sent(RTC_FRAME_TYPE, sequence_counter);
	}

	return len;
}

static int rtc_gen_and_send_frames(struct thread_context *thread_context, int socket_fd,
				   struct sockaddr_ll *destination, uint64_t sequence_counter_begin)
{
	struct timespec tx_time = {};
	int len, i;

	clock_gettime(app_config.application_clock_id, &tx_time);

	for (i = 0; i < app_config.rtc_num_frames_per_cycle; i++) {
		struct prepare_frame_config frame_config;
		int err;

		frame_config.mode = app_config.rtc_security_mode;
		frame_config.security_context = thread_context->tx_security_context;
		frame_config.iv_prefix = (const unsigned char *)app_config.rtc_security_iv_prefix;
		frame_config.payload_pattern = thread_context->payload_pattern;
		frame_config.payload_pattern_length = thread_context->payload_pattern_length;
		frame_config.frame_data = frame_idx(thread_context->tx_frame_data, i);
		frame_config.frame_length = app_config.rtc_frame_length;
		frame_config.num_frames_per_cycle = app_config.rtc_num_frames_per_cycle;
		frame_config.sequence_counter = sequence_counter_begin + i;
		frame_config.tx_timestamp = ts_to_ns(&tx_time);
		frame_config.meta_data_offset = thread_context->meta_data_offset;

		err = prepare_frame_for_tx(&frame_config);
		if (err)
			log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to prepare frame for Tx!\n");
	}

	/* Send it */
	len = rtc_send_messages(thread_context, socket_fd, destination,
				thread_context->tx_frame_data, app_config.rtc_num_frames_per_cycle);

	for (i = 0; i < len; i++)
		stat_frame_sent(RTC_FRAME_TYPE, sequence_counter_begin + i);

	return len;
}

static void rtc_gen_and_send_xdp_frames(struct thread_context *thread_context,
					struct xdp_socket *xsk, uint64_t sequence_counter,
					uint32_t *frame_number)
{
	struct xdp_gen_config xdp;

	xdp.mode = app_config.rtc_security_mode;
	xdp.security_context = thread_context->tx_security_context;
	xdp.iv_prefix = (const unsigned char *)app_config.rtc_security_iv_prefix;
	xdp.payload_pattern = thread_context->payload_pattern;
	xdp.payload_pattern_length = thread_context->payload_pattern_length;
	xdp.frame_length = app_config.rtc_frame_length;
	xdp.num_frames_per_cycle = app_config.rtc_num_frames_per_cycle;
	xdp.frame_number = frame_number;
	xdp.sequence_counter_begin = sequence_counter;
	xdp.meta_data_offset = thread_context->meta_data_offset;
	xdp.frame_type = RTC_FRAME_TYPE;

	xdp_gen_and_send_frames(xsk, &xdp);
}

static void *rtc_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	size_t received_frames_length = MAX_FRAME_SIZE * app_config.rtc_num_frames_per_cycle;
	struct security_context *security_context = thread_context->tx_security_context;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	unsigned char *received_frames = thread_context->rx_frame_data;
	const bool mirror_enabled = app_config.rtc_rx_mirror_enabled;
	struct sockaddr_ll destination;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	unsigned int if_index;
	int ret, socket_fd;

	socket_fd = thread_context->socket_fd;

	ret = get_interface_mac_address(app_config.rtc_interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to get Source MAC address!\n");
		return NULL;
	}

	if_index = if_nametoindex(app_config.rtc_interface);
	if (!if_index) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: if_nametoindex() failed!\n");
		return NULL;
	}

	memset(&destination, '\0', sizeof(destination));
	destination.sll_family = PF_PACKET;
	destination.sll_ifindex = if_index;
	destination.sll_halen = ETH_ALEN;
	memcpy(destination.sll_addr, app_config.rtc_destination, ETH_ALEN);

	rtc_initialize_frames(thread_context->tx_frame_data, app_config.rtc_num_frames_per_cycle,
			      source, app_config.rtc_destination);

	prepare_openssl(security_context);
	rtc_initialize_frames(thread_context->payload_pattern, 1, source,
			      app_config.rtc_destination);
	thread_context->payload_pattern +=
		sizeof(struct vlan_ethernet_header) + sizeof(struct profinet_secure_header);
	thread_context->payload_pattern_length =
		app_config.rtc_frame_length - sizeof(struct vlan_ethernet_header) -
		sizeof(struct profinet_secure_header) - sizeof(struct security_checksum);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		if (!thread_context->is_first) {
			struct timespec timeout;

			/*
			 * Wait until signalled. These RTC frames have to be sent after the TSN Low
			 * frames.
			 */
			clock_gettime(CLOCK_MONOTONIC, &timeout);
			timeout.tv_sec++;

			pthread_mutex_lock(&thread_context->data_mutex);
			ret = pthread_cond_timedwait(&thread_context->data_cond_var,
						     &thread_context->data_mutex, &timeout);
			pthread_mutex_unlock(&thread_context->data_mutex);

			/* In case of shutdown a signal may be missing. */
			if (ret == ETIMEDOUT)
				continue;
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
			rtc_gen_and_send_frames(thread_context, socket_fd, &destination,
						sequence_counter);

			sequence_counter += app_config.rtc_num_frames_per_cycle;
		} else {
			size_t len, num_frames;

			ring_buffer_fetch(thread_context->mirror_buffer, received_frames,
					  received_frames_length, &len);

			/* Len should be a multiple of frame size */
			num_frames = len / app_config.rtc_frame_length;
			rtc_send_frames(thread_context, received_frames, num_frames, socket_fd,
					&destination);
		}

		/* Signal next Tx thread */
		if (thread_context->next) {
			pthread_mutex_lock(&thread_context->next->data_mutex);
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

	prepare_openssl(security_context);
	rtc_initialize_frames(thread_context->payload_pattern, 1, source,
			      app_config.rtc_destination);
	thread_context->payload_pattern +=
		sizeof(struct vlan_ethernet_header) + sizeof(struct profinet_secure_header);
	thread_context->payload_pattern_length =
		app_config.rtc_frame_length - sizeof(struct vlan_ethernet_header) -
		sizeof(struct profinet_secure_header) - sizeof(struct security_checksum);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		if (!thread_context->is_first) {
			struct timespec timeout;

			/*
			 * Wait until signalled. These RTC frames have to be sent after the TSN Low
			 * frames.
			 */
			clock_gettime(CLOCK_MONOTONIC, &timeout);
			timeout.tv_sec++;

			pthread_mutex_lock(&thread_context->data_mutex);
			ret = pthread_cond_timedwait(&thread_context->data_cond_var,
						     &thread_context->data_mutex, &timeout);
			pthread_mutex_unlock(&thread_context->data_mutex);

			/* In case of shutdown a signal may be missing. */
			if (ret == ETIMEDOUT)
				continue;
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
			rtc_gen_and_send_xdp_frames(thread_context, xsk, sequence_counter,
						    &frame_number);
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
	unsigned char plaintext[MAX_FRAME_SIZE];
	unsigned char new_frame[MAX_FRAME_SIZE];
	struct timespec tx_timespec_mirror = {};
	struct profinet_secure_header *srt;
	struct profinet_rt_header *rt;
	uint64_t sequence_counter;
	uint64_t tx_timestamp;
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

	clock_gettime(app_config.application_clock_id, &tx_timespec_mirror);

	/* Check cycle counter, frame id range and payload. */
	if (app_config.rtc_security_mode == SECURITY_MODE_NONE) {
		rt = p;
		p += sizeof(*rt);

		frame_id = be16toh(rt->frame_id);
		sequence_counter =
			meta_data_to_sequence_counter(&rt->meta_data, num_frames_per_cycle);

		tx_timestamp = meta_data_to_tx_timestamp(&rt->meta_data);
		tx_timestamp_to_meta_data(&rt->meta_data,
					  ts_to_ns(&tx_timespec_mirror) +
						  (app_config.application_tx_base_offset_ns -
						   app_config.application_rx_base_offset_ns));

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

		tx_timestamp = meta_data_to_tx_timestamp(&srt->meta_data);

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

		tx_timestamp_to_meta_data(&srt->meta_data,
					  ts_to_ns(&tx_timespec_mirror) +
						  (app_config.application_tx_base_offset_ns -
						   app_config.application_rx_base_offset_ns));
		security_encrypt(security_context, NULL, 0, begin_of_aad_data, size_of_aad_data,
				 (unsigned char *)&iv, NULL, begin_of_security_checksum);
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

		tx_timestamp = meta_data_to_tx_timestamp(&srt->meta_data);

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

		tx_timestamp_to_meta_data(&srt->meta_data,
					  ts_to_ns(&tx_timespec_mirror) +
						  (app_config.application_tx_base_offset_ns -
						   app_config.application_rx_base_offset_ns));

		security_encrypt(security_context, thread_context->payload_pattern,
				 thread_context->payload_pattern_length, begin_of_aad_data,
				 size_of_aad_data, (unsigned char *)&iv, begin_of_ciphertext,
				 begin_of_security_checksum);
	}

	out_of_order = sequence_counter != thread_context->rx_sequence_counter;
	payload_mismatch = memcmp(p, expected_pattern, expected_pattern_length);
	frame_id_mismatch = frame_id != RTC_FRAMEID;

	stat_frame_received(RTC_FRAME_TYPE, sequence_counter, out_of_order, payload_mismatch,
			    frame_id_mismatch, tx_timestamp);

	if (frame_id_mismatch)
		log_message(LOG_LEVEL_WARNING,
			    "RtcRx: frame[%" PRIu64 "] FrameId mismatch: 0x%4x!\n",
			    sequence_counter, RTC_FRAMEID);

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
					app_config.rtc_vid | app_config.rtc_pcp << VLAN_PCP_SHIFT);

		/* Swap mac addresses inline */
		swap_mac_addresses(frame_data, len);
	} else {
		/* Build new frame for Tx with VLAN info. */
		build_vlan_frame_from_rx(frame_data, len, new_frame, sizeof(new_frame),
					 ETH_P_PROFINET_RT,
					 app_config.rtc_vid | app_config.rtc_pcp << VLAN_PCP_SHIFT);

		/* Store the new frame. */
		ring_buffer_add(thread_context->mirror_buffer, new_frame,
				len + sizeof(struct vlan_header));
	}

	return 0;
}

static void *rtc_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	struct timespec wakeup_time;
	int socket_fd, ret;

	socket_fd = thread_context->socket_fd;

	prepare_openssl(thread_context->rx_security_context);

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "RtcRx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		struct packet_receive_request recv_req = {
			.traffic_class = stat_frame_type_to_string(RTC_FRAME_TYPE),
			.socket_fd = socket_fd,
			.receive_function = rtc_rx_frame,
			.data = thread_context,
		};

		/* Wait until next period. */
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

		/* Receive Rtc frames. */
		packet_receive_messages(thread_context->packet_context, &recv_req);
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

	/* For XDP the frames are stored in a umem area. That memory is part of the socket. */
	if (!app_config.rtc_xdp_enabled) {
		thread_context->packet_context = packet_init(app_config.rtc_num_frames_per_cycle);
		if (!thread_context->packet_context) {
			fprintf(stderr, "Failed to allocate Rtc packet context!\n");
			ret = -ENOMEM;
			goto err_packet;
		}

		thread_context->tx_frame_data =
			calloc(app_config.rtc_num_frames_per_cycle, MAX_FRAME_SIZE);
		if (!thread_context->tx_frame_data) {
			fprintf(stderr, "Failed to allocate RtcTxFrameData!\n");
			ret = -ENOMEM;
			goto err_tx;
		}

		thread_context->rx_frame_data =
			calloc(app_config.rtc_num_frames_per_cycle, MAX_FRAME_SIZE);
		if (!thread_context->rx_frame_data) {
			fprintf(stderr, "Failed to allocate RtcRxFrameData!\n");
			ret = -ENOMEM;
			goto err_rx;
		}
	}

	thread_context->payload_pattern = calloc(1, MAX_FRAME_SIZE);
	if (!thread_context->payload_pattern) {
		fprintf(stderr, "Failed to allocate RtcPayloadPattern!\n");
		ret = -ENOMEM;
		goto err_payload;
	}
	thread_context->payload_pattern_length = MAX_FRAME_SIZE;

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
		thread_context->mirror_buffer =
			ring_buffer_allocate(MAX_FRAME_SIZE * app_config.rtc_num_frames_per_cycle);
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

	thread_context->meta_data_offset =
		get_meta_data_offset(RTC_FRAME_TYPE, app_config.rtc_security_mode);

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
	free(thread_context->payload_pattern);
err_payload:
	free(thread_context->rx_frame_data);
err_rx:
	free(thread_context->tx_frame_data);
err_tx:
	packet_free(thread_context->packet_context);
err_packet:
	return ret;
}

void rtc_threads_free(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	if (thread_context->payload_pattern) {
		thread_context->payload_pattern -=
			sizeof(struct vlan_ethernet_header) + sizeof(struct profinet_secure_header);
		free(thread_context->payload_pattern);
	}

	security_exit(thread_context->tx_security_context);
	security_exit(thread_context->rx_security_context);

	ring_buffer_free(thread_context->mirror_buffer);

	packet_free(thread_context->packet_context);
	free(thread_context->tx_frame_data);
	free(thread_context->rx_frame_data);

	if (thread_context->socket_fd > 0)
		close(thread_context->socket_fd);

	if (thread_context->xsk)
		xdp_close_socket(thread_context->xsk, app_config.rtc_interface,
				 app_config.rtc_xdp_skb_mode);
}

void rtc_threads_wait_for_finish(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	if (thread_context->rx_task_id)
		pthread_join(thread_context->rx_task_id, NULL);
	if (thread_context->tx_task_id)
		pthread_join(thread_context->tx_task_id, NULL);
}
