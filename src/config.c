// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

#include <linux/if_ether.h>

#include "config.h"
#include "net_def.h"
#include "security.h"
#include "utils.h"

#include "dcp_thread.h"
#include "layer2_thread.h"
#include "lldp_thread.h"
#include "rta_thread.h"
#include "rtc_thread.h"
#include "tsn_thread.h"
#include "udp_thread.h"

struct application_config app_config;

/*
 * The configuration file is YAML based. Use libyaml to parse it.
 */
int config_read_from_file(const char *config_file)
{
	int ret, state_key = 0;
	yaml_parser_t parser;
	yaml_token_t token;
	const char *value;
	char *key = NULL;
	FILE *f;

	if (!config_file)
		return -EINVAL;

	f = fopen(config_file, "r");
	if (!f) {
		perror("fopen() failed");
		return -EIO;
	}

	ret = yaml_parser_initialize(&parser);
	if (!ret) {
		ret = -EINVAL;
		fprintf(stderr, "Failed to initialize YAML parser\n");
		goto err_yaml;
	}

	yaml_parser_set_input_file(&parser, f);

	do {
		char *endptr;

		ret = yaml_parser_scan(&parser, &token);
		if (!ret) {
			ret = -EINVAL;
			fprintf(stderr, "Failed to parse YAML file!\n");
			goto err_parse;
		}

		switch (token.type) {
		case YAML_KEY_TOKEN:
			state_key = 1;
			break;
		case YAML_VALUE_TOKEN:
			state_key = 0;
			break;
		case YAML_SCALAR_TOKEN:
			value = (const char *)token.data.scalar.value;
			if (state_key) {
				/* Save key */
				key = strdup(value);
				if (!key) {
					fprintf(stderr, "No memory left!\n");
					goto err_parse;
				}

				continue;
			}

			if (!key)
				continue;

			/* Switch value */
			CONFIG_STORE_CLOCKID_PARAM(application_clock_id);
			CONFIG_STORE_ULONG_PARAM(application_base_cycle_time_ns);
			CONFIG_STORE_ULONG_PARAM(application_base_start_time_ns);
			CONFIG_STORE_ULONG_PARAM(application_tx_base_offset_ns);
			CONFIG_STORE_ULONG_PARAM(application_rx_base_offset_ns);
			CONFIG_STORE_STRING_PARAM(application_xdp_program);

			CONFIG_STORE_BOOL_PARAM(tsn_high_enabled);
			CONFIG_STORE_BOOL_PARAM(tsn_high_xdp_enabled);
			CONFIG_STORE_BOOL_PARAM(tsn_high_xdp_skb_mode);
			CONFIG_STORE_BOOL_PARAM(tsn_high_xdp_zc_mode);
			CONFIG_STORE_BOOL_PARAM(tsn_high_xdp_wakeup_mode);
			CONFIG_STORE_BOOL_PARAM(tsn_high_xdp_busy_poll_mode);
			CONFIG_STORE_BOOL_PARAM(tsn_high_tx_time_enabled);
			CONFIG_STORE_BOOL_PARAM(tsn_high_ignore_rx_errors);
			CONFIG_STORE_ULONG_PARAM(tsn_high_tx_time_offset_ns);
			CONFIG_STORE_INT_PARAM(tsn_high_vid);
			CONFIG_STORE_ULONG_PARAM(tsn_high_num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM(tsn_high_payload_pattern);
			CONFIG_STORE_ULONG_PARAM(tsn_high_frame_length);
			CONFIG_STORE_SECURITY_MODE_PARAM(tsn_high_security_mode);
			CONFIG_STORE_SECURITY_ALGORITHM_PARAM(tsn_high_security_algorithm);
			CONFIG_STORE_STRING_PARAM(tsn_high_security_key);
			CONFIG_STORE_STRING_PARAM(tsn_high_security_iv_prefix);
			CONFIG_STORE_INT_PARAM(tsn_high_rx_queue);
			CONFIG_STORE_INT_PARAM(tsn_high_tx_queue);
			CONFIG_STORE_INT_PARAM(tsn_high_socket_priority);
			CONFIG_STORE_INT_PARAM(tsn_high_tx_thread_priority);
			CONFIG_STORE_INT_PARAM(tsn_high_rx_thread_priority);
			CONFIG_STORE_INT_PARAM(tsn_high_tx_thread_cpu);
			CONFIG_STORE_INT_PARAM(tsn_high_rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM(tsn_high_interface);
			CONFIG_STORE_MAC_PARAM(tsn_high_destination);

			CONFIG_STORE_BOOL_PARAM(tsn_low_enabled);
			CONFIG_STORE_BOOL_PARAM(tsn_low_xdp_enabled);
			CONFIG_STORE_BOOL_PARAM(tsn_low_xdp_skb_mode);
			CONFIG_STORE_BOOL_PARAM(tsn_low_xdp_zc_mode);
			CONFIG_STORE_BOOL_PARAM(tsn_low_xdp_wakeup_mode);
			CONFIG_STORE_BOOL_PARAM(tsn_low_xdp_busy_poll_mode);
			CONFIG_STORE_BOOL_PARAM(tsn_low_tx_time_enabled);
			CONFIG_STORE_BOOL_PARAM(tsn_low_ignore_rx_errors);
			CONFIG_STORE_ULONG_PARAM(tsn_low_tx_time_offset_ns);
			CONFIG_STORE_INT_PARAM(tsn_low_vid);
			CONFIG_STORE_ULONG_PARAM(tsn_low_num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM(tsn_low_payload_pattern);
			CONFIG_STORE_ULONG_PARAM(tsn_low_frame_length);
			CONFIG_STORE_SECURITY_MODE_PARAM(tsn_low_security_mode);
			CONFIG_STORE_SECURITY_ALGORITHM_PARAM(tsn_low_security_algorithm);
			CONFIG_STORE_STRING_PARAM(tsn_low_security_key);
			CONFIG_STORE_STRING_PARAM(tsn_low_security_iv_prefix);
			CONFIG_STORE_INT_PARAM(tsn_low_rx_queue);
			CONFIG_STORE_INT_PARAM(tsn_low_tx_queue);
			CONFIG_STORE_INT_PARAM(tsn_low_socket_priority);
			CONFIG_STORE_INT_PARAM(tsn_low_tx_thread_priority);
			CONFIG_STORE_INT_PARAM(tsn_low_rx_thread_priority);
			CONFIG_STORE_INT_PARAM(tsn_low_tx_thread_cpu);
			CONFIG_STORE_INT_PARAM(tsn_low_rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM(tsn_low_interface);
			CONFIG_STORE_MAC_PARAM(tsn_low_destination);

			CONFIG_STORE_BOOL_PARAM(rtc_enabled);
			CONFIG_STORE_BOOL_PARAM(rtc_xdp_enabled);
			CONFIG_STORE_BOOL_PARAM(rtc_xdp_skb_mode);
			CONFIG_STORE_BOOL_PARAM(rtc_xdp_zc_mode);
			CONFIG_STORE_BOOL_PARAM(rtc_xdp_wakeup_mode);
			CONFIG_STORE_BOOL_PARAM(rtc_xdp_busy_poll_mode);
			CONFIG_STORE_BOOL_PARAM(rtc_ignore_rx_errors);
			CONFIG_STORE_INT_PARAM(rtc_vid);
			CONFIG_STORE_ULONG_PARAM(rtc_num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM(rtc_payload_pattern);
			CONFIG_STORE_ULONG_PARAM(rtc_frame_length);
			CONFIG_STORE_SECURITY_MODE_PARAM(rtc_security_mode);
			CONFIG_STORE_SECURITY_ALGORITHM_PARAM(rtc_security_algorithm);
			CONFIG_STORE_STRING_PARAM(rtc_security_key);
			CONFIG_STORE_STRING_PARAM(rtc_security_iv_prefix);
			CONFIG_STORE_INT_PARAM(rtc_rx_queue);
			CONFIG_STORE_INT_PARAM(rtc_tx_queue);
			CONFIG_STORE_INT_PARAM(rtc_socket_priority);
			CONFIG_STORE_INT_PARAM(rtc_tx_thread_priority);
			CONFIG_STORE_INT_PARAM(rtc_rx_thread_priority);
			CONFIG_STORE_INT_PARAM(rtc_tx_thread_cpu);
			CONFIG_STORE_INT_PARAM(rtc_rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM(rtc_interface);
			CONFIG_STORE_MAC_PARAM(rtc_destination);

			CONFIG_STORE_BOOL_PARAM(rta_enabled);
			CONFIG_STORE_BOOL_PARAM(rta_xdp_enabled);
			CONFIG_STORE_BOOL_PARAM(rta_xdp_skb_mode);
			CONFIG_STORE_BOOL_PARAM(rta_xdp_zc_mode);
			CONFIG_STORE_BOOL_PARAM(rta_xdp_wakeup_mode);
			CONFIG_STORE_BOOL_PARAM(rta_xdp_busy_poll_mode);
			CONFIG_STORE_BOOL_PARAM(rta_ignore_rx_errors);
			CONFIG_STORE_INT_PARAM(rta_vid);
			CONFIG_STORE_ULONG_PARAM(rta_burst_period_ns);
			CONFIG_STORE_ULONG_PARAM(rta_num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM(rta_payload_pattern);
			CONFIG_STORE_ULONG_PARAM(rta_frame_length);
			CONFIG_STORE_SECURITY_MODE_PARAM(rta_security_mode);
			CONFIG_STORE_SECURITY_ALGORITHM_PARAM(rta_security_algorithm);
			CONFIG_STORE_STRING_PARAM(rta_security_key);
			CONFIG_STORE_STRING_PARAM(rta_security_iv_prefix);
			CONFIG_STORE_INT_PARAM(rta_rx_queue);
			CONFIG_STORE_INT_PARAM(rta_tx_queue);
			CONFIG_STORE_INT_PARAM(rta_socket_priority);
			CONFIG_STORE_INT_PARAM(rta_tx_thread_priority);
			CONFIG_STORE_INT_PARAM(rta_rx_thread_priority);
			CONFIG_STORE_INT_PARAM(rta_tx_thread_cpu);
			CONFIG_STORE_INT_PARAM(rta_rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM(rta_interface);
			CONFIG_STORE_MAC_PARAM(rta_destination);

			CONFIG_STORE_BOOL_PARAM(dcp_enabled);
			CONFIG_STORE_BOOL_PARAM(dcp_ignore_rx_errors);
			CONFIG_STORE_INT_PARAM(dcp_vid);
			CONFIG_STORE_ULONG_PARAM(dcp_burst_period_ns);
			CONFIG_STORE_ULONG_PARAM(dcp_num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM(dcp_payload_pattern);
			CONFIG_STORE_ULONG_PARAM(dcp_frame_length);
			CONFIG_STORE_INT_PARAM(dcp_rx_queue);
			CONFIG_STORE_INT_PARAM(dcp_tx_queue);
			CONFIG_STORE_INT_PARAM(dcp_socket_priority);
			CONFIG_STORE_INT_PARAM(dcp_tx_thread_priority);
			CONFIG_STORE_INT_PARAM(dcp_rx_thread_priority);
			CONFIG_STORE_INT_PARAM(dcp_tx_thread_cpu);
			CONFIG_STORE_INT_PARAM(dcp_rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM(dcp_interface);
			CONFIG_STORE_MAC_PARAM(dcp_destination);

			CONFIG_STORE_BOOL_PARAM(lldp_enabled);
			CONFIG_STORE_BOOL_PARAM(lldp_ignore_rx_errors);
			CONFIG_STORE_ULONG_PARAM(lldp_burst_period_ns);
			CONFIG_STORE_ULONG_PARAM(lldp_num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM(lldp_payload_pattern);
			CONFIG_STORE_ULONG_PARAM(lldp_frame_length);
			CONFIG_STORE_INT_PARAM(lldp_rx_queue);
			CONFIG_STORE_INT_PARAM(lldp_tx_queue);
			CONFIG_STORE_INT_PARAM(lldp_socket_priority);
			CONFIG_STORE_INT_PARAM(lldp_tx_thread_priority);
			CONFIG_STORE_INT_PARAM(lldp_rx_thread_priority);
			CONFIG_STORE_INT_PARAM(lldp_tx_thread_cpu);
			CONFIG_STORE_INT_PARAM(lldp_rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM(lldp_interface);
			CONFIG_STORE_MAC_PARAM(lldp_destination);

			CONFIG_STORE_BOOL_PARAM(udp_high_enabled);
			CONFIG_STORE_BOOL_PARAM(udp_high_ignore_rx_errors);
			CONFIG_STORE_ULONG_PARAM(udp_high_burst_period_ns);
			CONFIG_STORE_ULONG_PARAM(udp_high_num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM(udp_high_payload_pattern);
			CONFIG_STORE_ULONG_PARAM(udp_high_frame_length);
			CONFIG_STORE_INT_PARAM(udp_high_rx_queue);
			CONFIG_STORE_INT_PARAM(udp_high_tx_queue);
			CONFIG_STORE_INT_PARAM(udp_high_socket_priority);
			CONFIG_STORE_INT_PARAM(udp_high_tx_thread_priority);
			CONFIG_STORE_INT_PARAM(udp_high_rx_thread_priority);
			CONFIG_STORE_INT_PARAM(udp_high_tx_thread_cpu);
			CONFIG_STORE_INT_PARAM(udp_high_rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM(udp_high_interface);
			CONFIG_STORE_STRING_PARAM(udp_high_port);
			CONFIG_STORE_STRING_PARAM(udp_high_destination);
			CONFIG_STORE_STRING_PARAM(udp_high_source);

			CONFIG_STORE_BOOL_PARAM(udp_low_enabled);
			CONFIG_STORE_BOOL_PARAM(udp_low_ignore_rx_errors);
			CONFIG_STORE_ULONG_PARAM(udp_low_burst_period_ns);
			CONFIG_STORE_ULONG_PARAM(udp_low_num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM(udp_low_payload_pattern);
			CONFIG_STORE_ULONG_PARAM(udp_low_frame_length);
			CONFIG_STORE_INT_PARAM(udp_low_rx_queue);
			CONFIG_STORE_INT_PARAM(udp_low_tx_queue);
			CONFIG_STORE_INT_PARAM(udp_low_socket_priority);
			CONFIG_STORE_INT_PARAM(udp_low_tx_thread_priority);
			CONFIG_STORE_INT_PARAM(udp_low_rx_thread_priority);
			CONFIG_STORE_INT_PARAM(udp_low_tx_thread_cpu);
			CONFIG_STORE_INT_PARAM(udp_low_rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM(udp_low_interface);
			CONFIG_STORE_STRING_PARAM(udp_low_port);
			CONFIG_STORE_STRING_PARAM(udp_low_destination);
			CONFIG_STORE_STRING_PARAM(udp_low_source);

			CONFIG_STORE_STRING_PARAM(generic_l2_name);
			CONFIG_STORE_BOOL_PARAM(generic_l2_enabled);
			CONFIG_STORE_BOOL_PARAM(generic_l2_xdp_enabled);
			CONFIG_STORE_BOOL_PARAM(generic_l2_xdp_skb_mode);
			CONFIG_STORE_BOOL_PARAM(generic_l2_xdp_zc_mode);
			CONFIG_STORE_BOOL_PARAM(generic_l2_xdp_wakeup_mode);
			CONFIG_STORE_BOOL_PARAM(generic_l2_xdp_busy_poll_mode);
			CONFIG_STORE_BOOL_PARAM(generic_l2_tx_time_enabled);
			CONFIG_STORE_BOOL_PARAM(generic_l2_ignore_rx_errors);
			CONFIG_STORE_ULONG_PARAM(generic_l2_tx_time_offset_ns);
			CONFIG_STORE_INT_PARAM(generic_l2_vid);
			CONFIG_STORE_INT_PARAM(generic_l2_pcp);
			CONFIG_STORE_ETHER_TYPE(generic_l2_ether_type);
			CONFIG_STORE_ULONG_PARAM(generic_l2_num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM(generic_l2_payload_pattern);
			CONFIG_STORE_ULONG_PARAM(generic_l2_frame_length);
			CONFIG_STORE_INT_PARAM(generic_l2_rx_queue);
			CONFIG_STORE_INT_PARAM(generic_l2_tx_queue);
			CONFIG_STORE_INT_PARAM(generic_l2_socket_priority);
			CONFIG_STORE_INT_PARAM(generic_l2_tx_thread_priority);
			CONFIG_STORE_INT_PARAM(generic_l2_rx_thread_priority);
			CONFIG_STORE_INT_PARAM(generic_l2_tx_thread_cpu);
			CONFIG_STORE_INT_PARAM(generic_l2_rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM(generic_l2_interface);
			CONFIG_STORE_MAC_PARAM(generic_l2_destination);

			CONFIG_STORE_ULONG_PARAM(log_thread_period_ns);
			CONFIG_STORE_INT_PARAM(log_thread_priority);
			CONFIG_STORE_INT_PARAM(log_thread_cpu);
			CONFIG_STORE_STRING_PARAM(log_file);
			CONFIG_STORE_STRING_PARAM(log_level);

			CONFIG_STORE_BOOL_PARAM(debug_stop_trace_on_rtt);
			CONFIG_STORE_BOOL_PARAM(debug_stop_trace_on_error);
			CONFIG_STORE_ULONG_PARAM(debug_stop_trace_rtt_limit_ns);
			CONFIG_STORE_BOOL_PARAM(debug_monitor_mode);
			CONFIG_STORE_MAC_PARAM(debug_monitor_destination);

			CONFIG_STORE_ULONG_PARAM(stats_collection_interval_ns);

			CONFIG_STORE_BOOL_PARAM(log_via_mqtt);
			CONFIG_STORE_INT_PARAM(log_via_mqtt_thread_priority);
			CONFIG_STORE_INT_PARAM(log_via_mqtt_thread_cpu);
			CONFIG_STORE_ULONG_PARAM(log_via_mqtt_thread_period_ns);
			CONFIG_STORE_STRING_PARAM(log_via_mqtt_broker_ip);
			CONFIG_STORE_INT_PARAM(log_via_mqtt_broker_port);
			CONFIG_STORE_INT_PARAM(log_via_mqtt_keep_alive_secs);
			CONFIG_STORE_STRING_PARAM(log_via_mqtt_measurement_name);

			if (key)
				free(key);

		default:
			break;
		}

		if (token.type != YAML_STREAM_END_TOKEN)
			yaml_token_delete(&token);

	} while (token.type != YAML_STREAM_END_TOKEN);

	ret = 0;

err_parse:
	yaml_token_delete(&token);
	yaml_parser_delete(&parser);

err_yaml:
	fclose(f);

	return ret;
}

void config_print_values(void)
{
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("ApplicationClockId=%s\n",
	       app_config.application_clock_id == CLOCK_TAI ? "CLOCK_TAI" : "CLOCK_MONOTONIC");
	printf("ApplicationBaseCycleTimeNS=%" PRIu64 "\n",
	       app_config.application_base_cycle_time_ns);
	printf("ApplicationBaseStartTimeNS=%" PRIu64 "\n",
	       app_config.application_base_start_time_ns);
	printf("ApplicationTxBaseOffsetNS=%" PRIu64 "\n", app_config.application_tx_base_offset_ns);
	printf("ApplicationRxBaseOffsetNS=%" PRIu64 "\n", app_config.application_rx_base_offset_ns);
	printf("ApplicationXdpProgram=%s\n", app_config.application_xdp_program);
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("TsnHighEnabled=%s\n", app_config.tsn_high_enabled ? "True" : "False");
	printf("TsnHighRxMirrorEnabled=%s\n",
	       app_config.tsn_high_rx_mirror_enabled ? "True" : "False");
	printf("TsnHighXdpEnabled=%s\n", app_config.tsn_high_xdp_enabled ? "True" : "False");
	printf("TsnHighXdpSkbMode=%s\n", app_config.tsn_high_xdp_skb_mode ? "True" : "False");
	printf("TsnHighXdpZcMode=%s\n", app_config.tsn_high_xdp_zc_mode ? "True" : "False");
	printf("TsnHighXdpWakeupMode=%s\n", app_config.tsn_high_xdp_wakeup_mode ? "True" : "False");
	printf("TsnHighXdpBusyPollMode=%s\n",
	       app_config.tsn_high_xdp_busy_poll_mode ? "True" : "False");
	printf("TsnHighTxTimeEnabled=%s\n", app_config.tsn_high_tx_time_enabled ? "True" : "False");
	printf("TsnHighIgnoreRxErrors=%s\n",
	       app_config.tsn_high_ignore_rx_errors ? "True" : "False");
	printf("TsnHighTxTimeOffsetNS=%" PRIu64 "\n", app_config.tsn_high_tx_time_offset_ns);
	printf("TsnHighVid=%d\n", app_config.tsn_high_vid);
	printf("TsnHighNumFramesPerCycle=%zu\n", app_config.tsn_high_num_frames_per_cycle);
	printf("TsnHighPayloadPattern=");
	print_payload_pattern(app_config.tsn_high_payload_pattern,
			      app_config.tsn_high_payload_pattern_length);
	printf("\n");
	printf("TsnHighFrameLength=%zu\n", app_config.tsn_high_frame_length);
	printf("TsnHighSecurityMode=%s\n",
	       security_mode_to_string(app_config.tsn_high_security_mode));
	printf("TsnHighSecurityAlgorithm=%s\n",
	       security_algorithm_to_string(app_config.tsn_high_security_algorithm));
	printf("TsnHighSecurityKey=%s\n", app_config.tsn_high_security_key);
	printf("TsnHighSecurityIvPrefix=%s\n", app_config.tsn_high_security_iv_prefix);
	printf("TsnHighRxQueue=%d\n", app_config.tsn_high_rx_queue);
	printf("TsnHighTxQueue=%d\n", app_config.tsn_high_tx_queue);
	printf("TsnHighSocketPriority=%d\n", app_config.tsn_high_socket_priority);
	printf("TsnHighTxThreadPriority=%d\n", app_config.tsn_high_tx_thread_priority);
	printf("TsnHighRxThreadPriority=%d\n", app_config.tsn_high_rx_thread_priority);
	printf("TsnHighTxThreadCpu=%d\n", app_config.tsn_high_tx_thread_cpu);
	printf("TsnHighRxThreadCpu=%d\n", app_config.tsn_high_rx_thread_cpu);
	printf("TsnHighInterface=%s\n", app_config.tsn_high_interface);
	printf("TsnHighDestination=");
	print_mac_address(app_config.tsn_high_destination);
	printf("\n");
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("TsnLowEnabled=%s\n", app_config.tsn_low_enabled ? "True" : "False");
	printf("TsnLowRxMirrorEnabled=%s\n",
	       app_config.tsn_low_rx_mirror_enabled ? "True" : "False");
	printf("TsnLowXdpEnabled=%s\n", app_config.tsn_low_xdp_enabled ? "True" : "False");
	printf("TsnLowXdpSkbMode=%s\n", app_config.tsn_low_xdp_skb_mode ? "True" : "False");
	printf("TsnLowXdpZcMode=%s\n", app_config.tsn_low_xdp_zc_mode ? "True" : "False");
	printf("TsnLowXdpWakeupMode=%s\n", app_config.tsn_low_xdp_wakeup_mode ? "True" : "False");
	printf("TsnLowXdpBusyPollMode=%s\n",
	       app_config.tsn_low_xdp_busy_poll_mode ? "True" : "False");
	printf("TsnLowTxTimeEnabled=%s\n", app_config.tsn_low_tx_time_enabled ? "True" : "False");
	printf("TsnLowIgnoreRxErrors=%s\n", app_config.tsn_low_ignore_rx_errors ? "True" : "False");
	printf("TsnLowTxTimeOffsetNS=%" PRIu64 "\n", app_config.tsn_low_tx_time_offset_ns);
	printf("TsnLowVid=%d\n", app_config.tsn_low_vid);
	printf("TsnLowNumFramesPerCycle=%zu\n", app_config.tsn_low_num_frames_per_cycle);
	printf("TsnLowPayloadPattern=");
	print_payload_pattern(app_config.tsn_low_payload_pattern,
			      app_config.tsn_low_payload_pattern_length);
	printf("\n");
	printf("TsnLowFrameLength=%zu\n", app_config.tsn_low_frame_length);
	printf("TsnLowSecurityMode=%s\n",
	       security_mode_to_string(app_config.tsn_low_security_mode));
	printf("TsnLowSecurityAlgorithm=%s\n",
	       security_algorithm_to_string(app_config.tsn_low_security_algorithm));
	printf("TsnLowSecurityKey=%s\n", app_config.tsn_low_security_key);
	printf("TsnLowSecurityIvPrefix=%s\n", app_config.tsn_low_security_iv_prefix);
	printf("TsnLowRxQueue=%d\n", app_config.tsn_low_rx_queue);
	printf("TsnLowTxQueue=%d\n", app_config.tsn_low_tx_queue);
	printf("TsnLowSocketPriority=%d\n", app_config.tsn_low_socket_priority);
	printf("TsnLowTxThreadPriority=%d\n", app_config.tsn_low_tx_thread_priority);
	printf("TsnLowRxThreadPriority=%d\n", app_config.tsn_low_rx_thread_priority);
	printf("TsnLowTxThreadCpu=%d\n", app_config.tsn_low_tx_thread_cpu);
	printf("TsnLowRxThreadCpu=%d\n", app_config.tsn_low_rx_thread_cpu);
	printf("TsnLowInterface=%s\n", app_config.tsn_low_interface);
	printf("TsnLowDestination=");
	print_mac_address(app_config.tsn_low_destination);
	printf("\n");
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("RtcEnabled=%s\n", app_config.rtc_enabled ? "True" : "False");
	printf("RtcRxMirrorEnabled=%s\n", app_config.rtc_rx_mirror_enabled ? "True" : "False");
	printf("RtcXdpEnabled=%s\n", app_config.rtc_xdp_enabled ? "True" : "False");
	printf("RtcXdpSkbMode=%s\n", app_config.rtc_xdp_skb_mode ? "True" : "False");
	printf("RtcXdpZcMode=%s\n", app_config.rtc_xdp_zc_mode ? "True" : "False");
	printf("RtcXdpWakeupMode=%s\n", app_config.rtc_xdp_wakeup_mode ? "True" : "False");
	printf("RtcXdpBusyPollMode=%s\n", app_config.rtc_xdp_busy_poll_mode ? "True" : "False");
	printf("RtcIgnoreRxErrors=%s\n", app_config.rtc_ignore_rx_errors ? "True" : "False");
	printf("RtcVid=%d\n", app_config.rtc_vid);
	printf("RtcNumFramesPerCycle=%zu\n", app_config.rtc_num_frames_per_cycle);
	printf("RtcPayloadPattern=");
	print_payload_pattern(app_config.rtc_payload_pattern,
			      app_config.rtc_payload_pattern_length);
	printf("\n");
	printf("RtcFrameLength=%zu\n", app_config.rtc_frame_length);
	printf("RtcSecurityMode=%s\n", security_mode_to_string(app_config.rtc_security_mode));
	printf("RtcSecurityAlgorithm=%s\n",
	       security_algorithm_to_string(app_config.rtc_security_algorithm));
	printf("RtcSecurityKey=%s\n", app_config.rtc_security_key);
	printf("RtcSecurityIvPrefix=%s\n", app_config.rtc_security_iv_prefix);
	printf("RtcRxQueue=%d\n", app_config.rtc_rx_queue);
	printf("RtcTxQueue=%d\n", app_config.rtc_tx_queue);
	printf("RtcSocketPriority=%d\n", app_config.rtc_socket_priority);
	printf("RtcTxThreadPriority=%d\n", app_config.rtc_tx_thread_priority);
	printf("RtcRxThreadPriority=%d\n", app_config.rtc_rx_thread_priority);
	printf("RtcTxThreadCpu=%d\n", app_config.rtc_tx_thread_cpu);
	printf("RtcRxThreadCpu=%d\n", app_config.rtc_rx_thread_cpu);
	printf("RtcInterface=%s\n", app_config.rtc_interface);
	printf("RtcDestination=");
	print_mac_address(app_config.rtc_destination);
	printf("\n");
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("RtaEnabled=%s\n", app_config.rta_enabled ? "True" : "False");
	printf("RtaRxMirrorEnabled=%s\n", app_config.rta_rx_mirror_enabled ? "True" : "False");
	printf("RtaXdpEnabled=%s\n", app_config.rta_xdp_enabled ? "True" : "False");
	printf("RtaXdpSkbMode=%s\n", app_config.rta_xdp_skb_mode ? "True" : "False");
	printf("RtaXdpZcMode=%s\n", app_config.rta_xdp_zc_mode ? "True" : "False");
	printf("RtaXdpWakeupMode=%s\n", app_config.rta_xdp_wakeup_mode ? "True" : "False");
	printf("RtaXdpBusyPollMode=%s\n", app_config.rta_xdp_busy_poll_mode ? "True" : "False");
	printf("RtaIgnoreRxErrors=%s\n", app_config.rta_ignore_rx_errors ? "True" : "False");
	printf("RtaVid=%d\n", app_config.rta_vid);
	printf("RtaBurstPeriodNS=%" PRIu64 "\n", app_config.rta_burst_period_ns);
	printf("RtaNumFramesPerCycle=%zu\n", app_config.rta_num_frames_per_cycle);
	printf("RtaPayloadPattern=");
	print_payload_pattern(app_config.rta_payload_pattern,
			      app_config.rta_payload_pattern_length);
	printf("\n");
	printf("RtaFrameLength=%zu\n", app_config.rta_frame_length);
	printf("RtaSecurityMode=%s\n", security_mode_to_string(app_config.rta_security_mode));
	printf("RtaSecurityAlgorithm=%s\n",
	       security_algorithm_to_string(app_config.rta_security_algorithm));
	printf("RtaSecurityKey=%s\n", app_config.rta_security_key);
	printf("RtaSecurityIvPrefix=%s\n", app_config.rta_security_iv_prefix);
	printf("RtaRxQueue=%d\n", app_config.rta_rx_queue);
	printf("RtaTxQueue=%d\n", app_config.rta_tx_queue);
	printf("RtaSocketPriority=%d\n", app_config.rta_socket_priority);
	printf("RtaTxThreadPriority=%d\n", app_config.rta_tx_thread_priority);
	printf("RtaRxThreadPriority=%d\n", app_config.rta_rx_thread_priority);
	printf("RtaTxThreadCpu=%d\n", app_config.rta_tx_thread_cpu);
	printf("RtaRxThreadCpu=%d\n", app_config.rta_rx_thread_cpu);
	printf("RtaInterface=%s\n", app_config.rta_interface);
	printf("RtaDestination=");
	print_mac_address(app_config.rta_destination);
	printf("\n");
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("DcpEnabled=%s\n", app_config.dcp_enabled ? "True" : "False");
	printf("DcpRxMirrorEnabled=%s\n", app_config.dcp_rx_mirror_enabled ? "True" : "False");
	printf("DcpIgnoreRxErrors=%s\n", app_config.dcp_ignore_rx_errors ? "True" : "False");
	printf("DcpVid=%d\n", app_config.dcp_vid);
	printf("DcpBurstPeriodNS=%" PRIu64 "\n", app_config.dcp_burst_period_ns);
	printf("DcpNumFramesPerCycle=%zu\n", app_config.dcp_num_frames_per_cycle);
	printf("DcpPayloadPattern=");
	print_payload_pattern(app_config.dcp_payload_pattern,
			      app_config.dcp_payload_pattern_length);
	printf("\n");
	printf("DcpFrameLength=%zu\n", app_config.dcp_frame_length);
	printf("DcpRxQueue=%d\n", app_config.dcp_rx_queue);
	printf("DcpTxQueue=%d\n", app_config.dcp_tx_queue);
	printf("DcpSocketPriority=%d\n", app_config.dcp_socket_priority);
	printf("DcpTxThreadPriority=%d\n", app_config.dcp_tx_thread_priority);
	printf("DcpRxThreadPriority=%d\n", app_config.dcp_rx_thread_priority);
	printf("DcpTxThreadCpu=%d\n", app_config.dcp_tx_thread_cpu);
	printf("DcpRxThreadCpu=%d\n", app_config.dcp_rx_thread_cpu);
	printf("DcpInterface=%s\n", app_config.dcp_interface);
	printf("DcpDestination=");
	print_mac_address(app_config.dcp_destination);
	printf("\n");
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("LldpEnabled=%s\n", app_config.lldp_enabled ? "True" : "False");
	printf("LldpRxMirrorEnabled=%s\n", app_config.lldp_rx_mirror_enabled ? "True" : "False");
	printf("LldpIgnoreRxErrors=%s\n", app_config.dcp_ignore_rx_errors ? "True" : "False");
	printf("LldpBurstPeriodNS=%" PRIu64 "\n", app_config.lldp_burst_period_ns);
	printf("LldpNumFramesPerCycle=%zu\n", app_config.lldp_num_frames_per_cycle);
	printf("LldpPayloadPattern=");
	print_payload_pattern(app_config.lldp_payload_pattern,
			      app_config.lldp_payload_pattern_length);
	printf("\n");
	printf("LldpFrameLength=%zu\n", app_config.lldp_frame_length);
	printf("LldpRxQueue=%d\n", app_config.lldp_rx_queue);
	printf("LldpTxQueue=%d\n", app_config.lldp_tx_queue);
	printf("LldpSocketPriority=%d\n", app_config.lldp_socket_priority);
	printf("LldpTxThreadPriority=%d\n", app_config.lldp_tx_thread_priority);
	printf("LldpRxThreadPriority=%d\n", app_config.lldp_rx_thread_priority);
	printf("LldpTxThreadCpu=%d\n", app_config.lldp_tx_thread_cpu);
	printf("LldpRxThreadCpu=%d\n", app_config.lldp_rx_thread_cpu);
	printf("LldpInterface=%s\n", app_config.lldp_interface);
	printf("LldpDestination=");
	print_mac_address(app_config.lldp_destination);
	printf("\n");
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("UdpHighEnabled=%s\n", app_config.udp_high_enabled ? "True" : "False");
	printf("UdpHighRxMirrorEnabled=%s\n",
	       app_config.udp_high_rx_mirror_enabled ? "True" : "False");
	printf("UdpHighIgnoreRxErrors=%s\n",
	       app_config.udp_high_ignore_rx_errors ? "True" : "False");
	printf("UdpHighBurstPeriodNS=%" PRIu64 "\n", app_config.udp_high_burst_period_ns);
	printf("UdpHighNumFramesPerCycle=%zu\n", app_config.udp_high_num_frames_per_cycle);
	printf("UdpHighPayloadPattern=");
	print_payload_pattern(app_config.udp_high_payload_pattern,
			      app_config.udp_high_payload_pattern_length);
	printf("\n");
	printf("UdpHighFrameLength=%zu\n", app_config.udp_high_frame_length);
	printf("UdpHighRxQueue=%d\n", app_config.udp_high_rx_queue);
	printf("UdpHighTxQueue=%d\n", app_config.udp_high_tx_queue);
	printf("UdpHighSocketPriority=%d\n", app_config.udp_high_socket_priority);
	printf("UdpHighTxThreadPriority=%d\n", app_config.udp_high_tx_thread_priority);
	printf("UdpHighRxThreadPriority=%d\n", app_config.udp_high_rx_thread_priority);
	printf("UdpHighTxThreadCpu=%d\n", app_config.udp_high_tx_thread_cpu);
	printf("UdpHighRxThreadCpu=%d\n", app_config.udp_high_rx_thread_cpu);
	printf("UdpHighInterface=%s\n", app_config.udp_high_interface);
	printf("UdpHighPort=%s\n", app_config.udp_high_port);
	printf("UdpHighDestination=%s\n", app_config.udp_high_destination);
	printf("UdpHighSource=%s\n", app_config.udp_high_source);
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("UdpLowEnabled=%s\n", app_config.udp_low_enabled ? "True" : "False");
	printf("UdpLowRxMirrorEnabled=%s\n",
	       app_config.udp_low_rx_mirror_enabled ? "True" : "False");
	printf("UdpLowIgnoreRxErrors=%s\n", app_config.udp_low_ignore_rx_errors ? "True" : "False");
	printf("UdpLowBurstPeriodNS=%" PRIu64 "\n", app_config.udp_low_burst_period_ns);
	printf("UdpLowNumFramesPerCycle=%zu\n", app_config.udp_low_num_frames_per_cycle);
	printf("UdpLowPayloadPattern=");
	print_payload_pattern(app_config.udp_low_payload_pattern,
			      app_config.udp_low_payload_pattern_length);
	printf("\n");
	printf("UdpLowFrameLength=%zu\n", app_config.udp_low_frame_length);
	printf("UdpLowRxQueue=%d\n", app_config.udp_low_rx_queue);
	printf("UdpLowTxQueue=%d\n", app_config.udp_low_tx_queue);
	printf("UdpLowSocketPriority=%d\n", app_config.udp_low_socket_priority);
	printf("UdpLowTxThreadPriority=%d\n", app_config.udp_low_tx_thread_priority);
	printf("UdpLowRxThreadPriority=%d\n", app_config.udp_low_rx_thread_priority);
	printf("UdpLowTxThreadCpu=%d\n", app_config.udp_low_tx_thread_cpu);
	printf("UdpLowRxThreadCpu=%d\n", app_config.udp_low_rx_thread_cpu);
	printf("UdpLowInterface=%s\n", app_config.udp_low_interface);
	printf("UdpLowPort=%s\n", app_config.udp_low_port);
	printf("UdpLowDestination=%s\n", app_config.udp_low_destination);
	printf("UdpLowSource=%s\n", app_config.udp_low_source);
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("GenericL2Name=%s\n", app_config.generic_l2_name);
	printf("GenericL2Enabled=%s\n", app_config.generic_l2_enabled ? "True" : "False");
	printf("GenericL2RxMirrorEnabled=%s\n",
	       app_config.generic_l2_rx_mirror_enabled ? "True" : "False");
	printf("GenericL2XdpEnabled=%s\n", app_config.generic_l2_xdp_enabled ? "True" : "False");
	printf("GenericL2XdpSkbMode=%s\n", app_config.generic_l2_xdp_skb_mode ? "True" : "False");
	printf("GenericL2XdpZcMode=%s\n", app_config.generic_l2_xdp_zc_mode ? "True" : "False");
	printf("GenericL2XdpWakeupMode=%s\n",
	       app_config.generic_l2_xdp_wakeup_mode ? "True" : "False");
	printf("GenericL2XdpBusyPollMode=%s\n",
	       app_config.generic_l2_xdp_busy_poll_mode ? "True" : "False");
	printf("GenericL2TxTimeEnabled=%s\n",
	       app_config.generic_l2_tx_time_enabled ? "True" : "False");
	printf("GenericL2IgnoreRxErrors=%s\n",
	       app_config.generic_l2_ignore_rx_errors ? "True" : "False");
	printf("GenericL2TxTimeOffsetNS=%" PRIu64 "\n", app_config.generic_l2_tx_time_offset_ns);
	printf("GenericL2Vid=%d\n", app_config.generic_l2_vid);
	printf("GenericL2Pcp=%d\n", app_config.generic_l2_pcp);
	printf("GenericL2EtherType=0x%04x\n", app_config.generic_l2_ether_type);
	printf("GenericL2NumFramesPerCycle=%zu\n", app_config.generic_l2_num_frames_per_cycle);
	printf("GenericL2PayloadPattern=");
	print_payload_pattern(app_config.generic_l2_payload_pattern,
			      app_config.generic_l2_payload_pattern_length);
	printf("\n");
	printf("GenericL2FrameLength=%zu\n", app_config.generic_l2_frame_length);
	printf("GenericL2RxQueue=%d\n", app_config.generic_l2_rx_queue);
	printf("GenericL2TxQueue=%d\n", app_config.generic_l2_tx_queue);
	printf("GenericL2SocketPriority=%d\n", app_config.generic_l2_socket_priority);
	printf("GenericL2TxThreadPriority=%d\n", app_config.generic_l2_tx_thread_priority);
	printf("GenericL2RxThreadPriority=%d\n", app_config.generic_l2_rx_thread_priority);
	printf("GenericL2TxThreadCpu=%d\n", app_config.generic_l2_tx_thread_cpu);
	printf("GenericL2RxThreadCpu=%d\n", app_config.generic_l2_rx_thread_cpu);
	printf("GenericL2Interface=%s\n", app_config.generic_l2_interface);
	printf("GenericL2Destination=");
	print_mac_address(app_config.generic_l2_destination);
	printf("\n");
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("LogThreadPeriodNS=%" PRIu64 "\n", app_config.log_thread_period_ns);
	printf("LogThreadPriority=%d\n", app_config.log_thread_priority);
	printf("LogThreadCpu=%d\n", app_config.log_thread_cpu);
	printf("LogFile=%s\n", app_config.log_file);
	printf("LogLevel=%s\n", app_config.log_level);
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("DebugStopTraceOnRtt=%s\n", app_config.debug_stop_trace_on_rtt ? "True" : "False");
	printf("DebugStopTraceOnError=%s\n",
	       app_config.debug_stop_trace_on_error ? "True" : "False");
	printf("DebugStopTraceLimitNS=%" PRIu64 "\n", app_config.debug_stop_trace_rtt_limit_ns);
	printf("DebugMonitorMode=%s\n", app_config.debug_monitor_mode ? "True" : "False");
	printf("DebugMonitorDestination=");
	print_mac_address(app_config.debug_monitor_destination);
	printf("\n");
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("StatsCollectionIntervalNS=%ld\n", app_config.stats_collection_interval_ns);
	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("LogViaMQTT=%s\n", app_config.log_via_mqtt ? "True" : "False");
	printf("LogViaMQTTThreadPriority=%d\n", app_config.log_via_mqtt_thread_priority);
	printf("LogViaMQTTThreadCpu=%d\n", app_config.log_via_mqtt_thread_cpu);
	printf("LogViaMQTTThreadPeriodNS=%ld\n", app_config.log_via_mqtt_thread_period_ns);
	printf("LogViaMQTTBrokerIP=%s\n", app_config.log_via_mqtt_broker_ip);
	printf("LogViaMQTTBrokerPort=%d\n", app_config.log_via_mqtt_broker_port);
	printf("LogViaMQTTKeepAliveSecs=%d\n", app_config.log_via_mqtt_keep_alive_secs);
	printf("LogViaMQTTMeasurementName=%s\n", app_config.log_via_mqtt_measurement_name);
	printf("--------------------------------------------------------------------------------"
	       "\n");
}

int config_set_defaults(bool mirror_enabled)
{
	static unsigned char default_debug_montitor_destination[] = {0x44, 0x44, 0x44,
								     0x44, 0x44, 0x44};
	static unsigned char default_lldp_destination[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};
	static unsigned char default_destination[] = {0xa8, 0xa1, 0x59, 0x2c, 0xa8, 0xdb};
	static unsigned char default_dcp_identify[] = {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00};
	static const char *default_log_via_mqtt_measurement_name = "testbench";
	static const char *default_udp_low_destination = "192.168.2.120";
	static const char *default_log_via_mqtt_broker_ip = "127.0.0.1";
	static const char *default_udp_low_source = "192.168.2.119";
	static const char *default_payload_pattern = "Payload";
	static const char *default_udp_low_port = "6666";
	static const char *default_log_level = "Debug";
	struct timespec current;
	int ret = -ENOMEM;

	clock_gettime(CLOCK_TAI, &current);

	/* Application scheduling configuration */
	app_config.application_clock_id = CLOCK_TAI;
	app_config.application_base_cycle_time_ns = 500000;
	app_config.application_base_start_time_ns = (current.tv_sec + 30) * NSEC_PER_SEC;
	app_config.application_tx_base_offset_ns = 400000;
	app_config.application_rx_base_offset_ns = 200000;
	app_config.application_xdp_program = NULL;

	/* TSN High */
	app_config.tsn_high_enabled = false;
	app_config.tsn_high_rx_mirror_enabled = mirror_enabled;
	app_config.tsn_high_xdp_enabled = false;
	app_config.tsn_high_xdp_skb_mode = false;
	app_config.tsn_high_xdp_zc_mode = false;
	app_config.tsn_high_xdp_wakeup_mode = true;
	app_config.tsn_high_xdp_busy_poll_mode = false;
	app_config.tsn_high_tx_time_enabled = false;
	app_config.tsn_high_ignore_rx_errors = false;
	app_config.tsn_high_tx_time_offset_ns = 0;
	app_config.tsn_high_vid = TSN_HIGH_VID_VALUE;
	app_config.tsn_high_num_frames_per_cycle = 0;
	app_config.tsn_high_payload_pattern = strdup(default_payload_pattern);
	if (!app_config.tsn_high_payload_pattern)
		goto out;
	app_config.tsn_high_payload_pattern_length = strlen(app_config.tsn_high_payload_pattern);
	app_config.tsn_high_frame_length = 200;
	app_config.tsn_high_security_mode = SECURITY_MODE_NONE;
	app_config.tsn_high_security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	app_config.tsn_high_security_key = NULL;
	app_config.tsn_high_security_iv_prefix = NULL;
	app_config.tsn_high_rx_queue = 1;
	app_config.tsn_high_tx_queue = 1;
	app_config.tsn_high_socket_priority = 1;
	app_config.tsn_high_tx_thread_priority = 98;
	app_config.tsn_high_rx_thread_priority = 98;
	app_config.tsn_high_tx_thread_cpu = 0;
	app_config.tsn_high_rx_thread_cpu = 0;
	strncpy(app_config.tsn_high_interface, "enp3s0", sizeof(app_config.tsn_high_interface) - 1);
	memcpy((void *)app_config.tsn_high_destination, default_destination, ETH_ALEN);

	/* TSN Low */
	app_config.tsn_low_enabled = false;
	app_config.tsn_low_rx_mirror_enabled = mirror_enabled;
	app_config.tsn_low_xdp_enabled = false;
	app_config.tsn_low_xdp_skb_mode = false;
	app_config.tsn_low_xdp_zc_mode = false;
	app_config.tsn_low_xdp_wakeup_mode = true;
	app_config.tsn_low_xdp_busy_poll_mode = false;
	app_config.tsn_low_tx_time_enabled = false;
	app_config.tsn_low_ignore_rx_errors = false;
	app_config.tsn_low_tx_time_offset_ns = 0;
	app_config.tsn_low_vid = TSN_LOW_VID_VALUE;
	app_config.tsn_low_num_frames_per_cycle = 0;
	app_config.tsn_low_payload_pattern = strdup(default_payload_pattern);
	if (!app_config.tsn_low_payload_pattern)
		goto out;
	app_config.tsn_low_payload_pattern_length = strlen(app_config.tsn_low_payload_pattern);
	app_config.tsn_low_frame_length = 200;
	app_config.tsn_low_security_mode = SECURITY_MODE_NONE;
	app_config.tsn_low_security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	app_config.tsn_low_security_key = NULL;
	app_config.tsn_low_security_iv_prefix = NULL;
	app_config.tsn_low_rx_queue = 1;
	app_config.tsn_low_tx_queue = 1;
	app_config.tsn_low_socket_priority = 1;
	app_config.tsn_low_tx_thread_priority = 98;
	app_config.tsn_low_rx_thread_priority = 98;
	app_config.tsn_low_tx_thread_cpu = 0;
	app_config.tsn_low_rx_thread_cpu = 0;
	strncpy(app_config.tsn_low_interface, "enp3s0", sizeof(app_config.tsn_low_interface) - 1);
	memcpy((void *)app_config.tsn_low_destination, default_destination, ETH_ALEN);

	/* Real Time Cyclic (RTC) */
	app_config.rtc_enabled = false;
	app_config.rtc_rx_mirror_enabled = mirror_enabled;
	app_config.rtc_xdp_enabled = false;
	app_config.rtc_xdp_skb_mode = false;
	app_config.rtc_xdp_zc_mode = false;
	app_config.rtc_xdp_wakeup_mode = true;
	app_config.rtc_xdp_busy_poll_mode = false;
	app_config.rtc_ignore_rx_errors = false;
	app_config.rtc_vid = PROFINET_RT_VID_VALUE;
	app_config.rtc_num_frames_per_cycle = 0;
	app_config.rtc_payload_pattern = strdup(default_payload_pattern);
	if (!app_config.rtc_payload_pattern)
		goto out;
	app_config.rtc_payload_pattern_length = strlen(app_config.rtc_payload_pattern);
	app_config.rtc_frame_length = 200;
	app_config.rtc_security_mode = SECURITY_MODE_NONE;
	app_config.rtc_security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	app_config.rtc_security_key = NULL;
	app_config.rtc_security_iv_prefix = NULL;
	app_config.rtc_rx_queue = 1;
	app_config.rtc_tx_queue = 1;
	app_config.rtc_socket_priority = 1;
	app_config.rtc_tx_thread_priority = 98;
	app_config.rtc_rx_thread_priority = 98;
	app_config.rtc_tx_thread_cpu = 0;
	app_config.rtc_rx_thread_cpu = 0;
	strncpy(app_config.rtc_interface, "enp3s0", sizeof(app_config.rtc_interface) - 1);
	memcpy((void *)app_config.rtc_destination, default_destination, ETH_ALEN);

	/* Real Time Acyclic (RTA) */
	app_config.rta_enabled = false;
	app_config.rta_rx_mirror_enabled = mirror_enabled;
	app_config.rta_xdp_enabled = false;
	app_config.rta_xdp_skb_mode = false;
	app_config.rta_xdp_zc_mode = false;
	app_config.rta_xdp_wakeup_mode = true;
	app_config.rta_xdp_busy_poll_mode = false;
	app_config.rta_ignore_rx_errors = false;
	app_config.rta_vid = PROFINET_RT_VID_VALUE;
	app_config.rta_burst_period_ns = 200000000;
	app_config.rta_num_frames_per_cycle = 0;
	app_config.rta_payload_pattern = strdup(default_payload_pattern);
	if (!app_config.rta_payload_pattern)
		goto out;
	app_config.rta_payload_pattern_length = strlen(app_config.rta_payload_pattern);
	app_config.rta_frame_length = 200;
	app_config.rta_security_mode = SECURITY_MODE_NONE;
	app_config.rta_security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	app_config.rta_security_key = NULL;
	app_config.rta_security_iv_prefix = NULL;
	app_config.rta_rx_queue = 1;
	app_config.rta_tx_queue = 1;
	app_config.rta_socket_priority = 1;
	app_config.rta_tx_thread_priority = 98;
	app_config.rta_rx_thread_priority = 98;
	app_config.rta_tx_thread_cpu = 0;
	app_config.rta_rx_thread_cpu = 0;
	strncpy(app_config.rta_interface, "enp3s0", sizeof(app_config.rta_interface) - 1);
	memcpy((void *)app_config.rta_destination, default_destination, ETH_ALEN);

	/* Discovery and Configuration Protocol (DCP) */
	app_config.dcp_enabled = false;
	app_config.dcp_ignore_rx_errors = false;
	app_config.dcp_rx_mirror_enabled = mirror_enabled;
	app_config.dcp_vid = PROFINET_RT_VID_VALUE;
	app_config.dcp_burst_period_ns = 2000000000;
	app_config.dcp_num_frames_per_cycle = 0;
	app_config.dcp_payload_pattern = strdup(default_payload_pattern);
	if (!app_config.dcp_payload_pattern)
		goto out;
	app_config.dcp_payload_pattern_length = strlen(app_config.dcp_payload_pattern);
	app_config.dcp_frame_length = 200;
	app_config.dcp_rx_queue = 1;
	app_config.dcp_tx_queue = 1;
	app_config.dcp_socket_priority = 1;
	app_config.dcp_tx_thread_priority = 98;
	app_config.dcp_rx_thread_priority = 98;
	app_config.dcp_tx_thread_cpu = 3;
	app_config.dcp_rx_thread_cpu = 3;
	strncpy(app_config.dcp_interface, "enp3s0", sizeof(app_config.dcp_interface) - 1);
	memcpy((void *)app_config.dcp_destination, default_dcp_identify, ETH_ALEN);

	/* Link Layer Discovery Protocol (LLDP) */
	app_config.lldp_enabled = false;
	app_config.lldp_ignore_rx_errors = false;
	app_config.lldp_rx_mirror_enabled = mirror_enabled;
	app_config.lldp_burst_period_ns = 5000000000;
	app_config.lldp_num_frames_per_cycle = 0;
	app_config.lldp_payload_pattern = strdup(default_payload_pattern);
	if (!app_config.lldp_payload_pattern)
		goto out;
	app_config.lldp_payload_pattern_length = strlen(app_config.lldp_payload_pattern);
	app_config.lldp_frame_length = 200;
	app_config.lldp_rx_queue = 1;
	app_config.lldp_tx_queue = 1;
	app_config.lldp_socket_priority = 1;
	app_config.lldp_tx_thread_priority = 98;
	app_config.lldp_rx_thread_priority = 98;
	app_config.lldp_tx_thread_cpu = 4;
	app_config.lldp_rx_thread_cpu = 4;
	strncpy(app_config.lldp_interface, "enp3s0", sizeof(app_config.lldp_interface) - 1);
	memcpy((void *)app_config.lldp_destination, default_lldp_destination, ETH_ALEN);

	/* User Datagram Protocol (UDP) High */
	app_config.udp_high_enabled = false;
	app_config.udp_high_ignore_rx_errors = false;
	app_config.udp_high_rx_mirror_enabled = mirror_enabled;
	app_config.udp_high_burst_period_ns = 1000000000;
	app_config.udp_high_num_frames_per_cycle = 0;
	app_config.udp_high_payload_pattern = strdup(default_payload_pattern);
	if (!app_config.udp_high_payload_pattern)
		goto out;
	app_config.udp_high_payload_pattern_length = strlen(app_config.udp_high_payload_pattern);
	app_config.udp_high_frame_length = 1400;
	app_config.udp_high_rx_queue = 0;
	app_config.udp_high_tx_queue = 0;
	app_config.udp_high_socket_priority = 0;
	app_config.udp_high_tx_thread_priority = 98;
	app_config.udp_high_rx_thread_priority = 98;
	app_config.udp_high_tx_thread_cpu = 5;
	app_config.udp_high_rx_thread_cpu = 5;
	strncpy(app_config.udp_high_interface, "enp3s0", sizeof(app_config.udp_high_interface) - 1);
	app_config.udp_high_port = strdup(default_udp_low_port);
	if (!app_config.udp_high_port)
		goto out;
	app_config.udp_high_destination = strdup(default_udp_low_destination);
	if (!app_config.udp_high_destination)
		goto out;
	app_config.udp_high_source = strdup(default_udp_low_source);
	if (!app_config.udp_high_source)
		goto out;

	/* User Datagram Protocol (UDP) Low */
	app_config.udp_low_enabled = false;
	app_config.udp_low_ignore_rx_errors = false;
	app_config.udp_low_rx_mirror_enabled = mirror_enabled;
	app_config.udp_low_burst_period_ns = 1000000000;
	app_config.udp_low_num_frames_per_cycle = 0;
	app_config.udp_low_payload_pattern = strdup(default_payload_pattern);
	if (!app_config.udp_low_payload_pattern)
		goto out;
	app_config.udp_low_payload_pattern_length = strlen(app_config.udp_low_payload_pattern);
	app_config.udp_low_frame_length = 1400;
	app_config.udp_low_rx_queue = 0;
	app_config.udp_low_tx_queue = 0;
	app_config.udp_low_socket_priority = 0;
	app_config.udp_low_tx_thread_priority = 98;
	app_config.udp_low_rx_thread_priority = 98;
	app_config.udp_low_tx_thread_cpu = 5;
	app_config.udp_low_rx_thread_cpu = 5;
	strncpy(app_config.udp_low_interface, "enp3s0", sizeof(app_config.udp_low_interface) - 1);
	app_config.udp_low_port = strdup(default_udp_low_port);
	if (!app_config.udp_low_port)
		goto out;
	app_config.udp_low_destination = strdup(default_udp_low_destination);
	if (!app_config.udp_low_destination)
		goto out;
	app_config.udp_low_source = strdup(default_udp_low_source);
	if (!app_config.udp_low_source)
		goto out;

	/* Generic L2 */
	app_config.generic_l2_name = strdup("GenericL2");
	if (!app_config.generic_l2_name)
		goto out;
	app_config.generic_l2_enabled = false;
	app_config.generic_l2_rx_mirror_enabled = mirror_enabled;
	app_config.generic_l2_xdp_enabled = false;
	app_config.generic_l2_xdp_skb_mode = false;
	app_config.generic_l2_xdp_zc_mode = false;
	app_config.generic_l2_xdp_wakeup_mode = true;
	app_config.generic_l2_xdp_busy_poll_mode = false;
	app_config.generic_l2_tx_time_enabled = false;
	app_config.generic_l2_ignore_rx_errors = false;
	app_config.generic_l2_tx_time_offset_ns = 0;
	app_config.generic_l2_vid = 100;
	app_config.generic_l2_pcp = 6;
	app_config.generic_l2_ether_type = 0xb62c;
	app_config.generic_l2_num_frames_per_cycle = 0;
	app_config.generic_l2_payload_pattern = strdup(default_payload_pattern);
	if (!app_config.generic_l2_payload_pattern)
		goto out;
	app_config.generic_l2_payload_pattern_length =
		strlen(app_config.generic_l2_payload_pattern);
	app_config.generic_l2_frame_length = 200;
	app_config.generic_l2_rx_queue = 1;
	app_config.generic_l2_tx_queue = 1;
	app_config.generic_l2_socket_priority = 1;
	app_config.generic_l2_tx_thread_priority = 90;
	app_config.generic_l2_rx_thread_priority = 90;
	app_config.generic_l2_tx_thread_cpu = 0;
	app_config.generic_l2_rx_thread_cpu = 0;
	strncpy(app_config.generic_l2_interface, "enp3s0",
		sizeof(app_config.generic_l2_interface) - 1);
	memcpy((void *)app_config.generic_l2_destination, default_destination, ETH_ALEN);

	/* Logging */
	app_config.log_thread_period_ns = 500000000;
	app_config.log_thread_priority = 1;
	app_config.log_thread_cpu = 7;
	app_config.log_file = strdup("reference.log");
	if (!app_config.log_file)
		goto out;
	app_config.log_level = strdup(default_log_level);
	if (!app_config.log_level)
		goto out;

	/* Debug */
	app_config.debug_stop_trace_on_rtt = false;
	app_config.debug_stop_trace_on_error = false;
	app_config.debug_stop_trace_rtt_limit_ns = 10000000;
	app_config.debug_monitor_mode = false;
	memcpy((void *)app_config.debug_monitor_destination, default_debug_montitor_destination,
	       ETH_ALEN);

	/* Stats */
	app_config.stats_collection_interval_ns = 1e9;

	/* LogViaMQTT */
	app_config.log_via_mqtt = false;
	app_config.log_via_mqtt_broker_port = 1883;
	app_config.log_via_mqtt_thread_priority = 1;
	app_config.log_via_mqtt_thread_cpu = 7;
	app_config.log_via_mqtt_keep_alive_secs = 60;
	app_config.log_via_mqtt_thread_period_ns = 1e9;
	app_config.log_via_mqtt_broker_ip = strdup(default_log_via_mqtt_broker_ip);
	if (!app_config.log_via_mqtt_broker_ip)
		goto out;

	app_config.log_via_mqtt_measurement_name = strdup(default_log_via_mqtt_measurement_name);
	if (!app_config.log_via_mqtt_measurement_name)
		goto out;
	return 0;
out:
	config_free();
	return ret;
}

static bool config_check_keys(const char *traffic_class, enum security_mode mode,
			      enum security_algorithm algorithm, size_t key_len,
			      size_t iv_prefix_len)
{
	const size_t expected_key_len = algorithm == SECURITY_ALGORITHM_AES128_GCM ? 16 : 32;

	if (mode == SECURITY_MODE_NONE)
		return true;

	if (iv_prefix_len != SECURITY_IV_PREFIX_LEN) {
		fprintf(stderr, "%s IV prefix length should be %d!\n", traffic_class,
			SECURITY_IV_PREFIX_LEN);
		return false;
	}

	if (expected_key_len != key_len) {
		fprintf(stderr, "%s key length mismatch!. Have %zu expected %zu for %s!\n",
			traffic_class, key_len, expected_key_len,
			security_algorithm_to_string(algorithm));
		return false;
	}

	return true;
}

bool config_sanity_check()
{
	const size_t min_secure_profinet_frame_size = sizeof(struct vlan_ethernet_header) +
						      sizeof(struct profinet_secure_header) +
						      sizeof(struct security_checksum);
	const size_t min_profinet_frame_size =
		sizeof(struct vlan_ethernet_header) + sizeof(struct profinet_rt_header);
	size_t min_frame_size;

	/*
	 * Perform configuration sanity checks. This includes:
	 *   - Traffic classes
	 *   - Frame lengths
	 *   - Limitations
	 */

	/* Either GenericL2 or PROFINET should be active. */
	if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(generic_l2) &&
	    (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(tsn_high) || CONFIG_IS_TRAFFIC_CLASS_ACTIVE(rtc) ||
	     CONFIG_IS_TRAFFIC_CLASS_ACTIVE(rta) || CONFIG_IS_TRAFFIC_CLASS_ACTIVE(dcp) ||
	     CONFIG_IS_TRAFFIC_CLASS_ACTIVE(lldp) || CONFIG_IS_TRAFFIC_CLASS_ACTIVE(udp_high) ||
	     CONFIG_IS_TRAFFIC_CLASS_ACTIVE(udp_low))) {
		fprintf(stderr, "Either use PROFINET or GenericL2!\n");
		fprintf(stderr, "For simulation of PROFINET and other middlewares in parallel "
				"start multiple instances of ref&mirror application(s) with "
				"different profiles!\n");
		return false;
	}

	/* Frame lengths */
	if (app_config.generic_l2_frame_length > GENL2_TX_FRAME_LENGTH ||
	    app_config.generic_l2_frame_length <
		    (sizeof(struct vlan_ethernet_header) + sizeof(struct generic_l2_header) +
		     app_config.generic_l2_payload_pattern_length)) {
		fprintf(stderr, "GenericL2FrameLength is invalid!\n");
		return false;
	}

	min_frame_size = app_config.tsn_high_security_mode == SECURITY_MODE_NONE
				 ? min_profinet_frame_size
				 : min_secure_profinet_frame_size;
	if (app_config.tsn_high_frame_length > TSN_TX_FRAME_LENGTH ||
	    app_config.tsn_high_frame_length <
		    (min_frame_size + app_config.tsn_high_payload_pattern_length)) {
		fprintf(stderr, "TsnHighFrameLength is invalid!\n");
		return false;
	}

	min_frame_size = app_config.tsn_low_security_mode == SECURITY_MODE_NONE
				 ? min_profinet_frame_size
				 : min_secure_profinet_frame_size;
	if (app_config.tsn_low_frame_length > TSN_TX_FRAME_LENGTH ||
	    app_config.tsn_low_frame_length <
		    (min_frame_size + app_config.tsn_low_payload_pattern_length)) {
		fprintf(stderr, "TsnLowFrameLength is invalid!\n");
		return false;
	}

	min_frame_size = app_config.rtc_security_mode == SECURITY_MODE_NONE
				 ? min_profinet_frame_size
				 : min_secure_profinet_frame_size;
	if (app_config.rtc_frame_length > RTC_TX_FRAME_LENGTH ||
	    app_config.rtc_frame_length <
		    (min_frame_size + app_config.rtc_payload_pattern_length)) {
		fprintf(stderr, "RtcFrameLength is invalid!\n");
		return false;
	}

	min_frame_size = app_config.rta_security_mode == SECURITY_MODE_NONE
				 ? min_profinet_frame_size
				 : min_secure_profinet_frame_size;
	if (app_config.rta_frame_length > RTA_TX_FRAME_LENGTH ||
	    app_config.rta_frame_length <
		    (min_frame_size + app_config.rta_payload_pattern_length)) {
		fprintf(stderr, "RtaFrameLength is invalid!\n");
		return false;
	}

	if (app_config.dcp_frame_length > DCP_TX_FRAME_LENGTH ||
	    app_config.dcp_frame_length <
		    (min_profinet_frame_size + app_config.dcp_payload_pattern_length)) {
		fprintf(stderr, "DcpFrameLength is invalid!\n");
		return false;
	}

	if (app_config.lldp_frame_length > LLDP_TX_FRAME_LENGTH ||
	    app_config.lldp_frame_length <
		    (sizeof(struct ethhdr) + sizeof(struct reference_meta_data) +
		     app_config.lldp_payload_pattern_length)) {
		fprintf(stderr, "LldpFrameLength is invalid!\n");
		return false;
	}

	if (app_config.udp_high_frame_length > UDP_TX_FRAME_LENGTH ||
	    app_config.udp_high_frame_length < (sizeof(struct reference_meta_data) +
						app_config.udp_high_payload_pattern_length)) {
		fprintf(stderr, "UdpHighFrameLength is invalid!\n");
		return false;
	}

	if (app_config.udp_low_frame_length > UDP_TX_FRAME_LENGTH ||
	    app_config.udp_low_frame_length < (sizeof(struct reference_meta_data) +
					       app_config.udp_low_payload_pattern_length)) {
		fprintf(stderr, "UdpLowFrameLength is invalid!\n");
		return false;
	}

	/* XDP and TxLauchTime combined doesn't work */
	if ((app_config.generic_l2_tx_time_enabled && app_config.generic_l2_xdp_enabled) ||
	    (app_config.tsn_high_tx_time_enabled && app_config.tsn_high_xdp_enabled) ||
	    (app_config.tsn_low_tx_time_enabled && app_config.tsn_low_xdp_enabled)) {
		fprintf(stderr, "TxTime and Xdp cannot be used at the same time!\n");
		return false;
	}

	/* XDP busy polling only works beginning with Linux kernel version v5.11 */
	if (!config_have_busy_poll() &&
	    (app_config.tsn_high_xdp_busy_poll_mode || app_config.tsn_low_xdp_busy_poll_mode ||
	     app_config.rtc_xdp_busy_poll_mode || app_config.rta_xdp_busy_poll_mode ||
	     app_config.generic_l2_xdp_busy_poll_mode)) {
		fprintf(stderr, "XDP busy polling selected, but not supported!\n");
		return false;
	}

	if (!config_have_mosquitto() && app_config.log_via_mqtt) {
		fprintf(stderr, "Log via Mosquito enabled, but not supported!\n");
		return false;
	}

	/* Check keys and IV */
	if (!config_check_keys("TsnHigh", app_config.tsn_high_security_mode,
			       app_config.tsn_high_security_algorithm,
			       app_config.tsn_high_security_key_length,
			       app_config.tsn_high_security_iv_prefix_length))
		return false;
	if (!config_check_keys("TsnLow", app_config.tsn_low_security_mode,
			       app_config.tsn_low_security_algorithm,
			       app_config.tsn_low_security_key_length,
			       app_config.tsn_low_security_iv_prefix_length))
		return false;
	if (!config_check_keys(
		    "Rtc", app_config.rtc_security_mode, app_config.rtc_security_algorithm,
		    app_config.rtc_security_key_length, app_config.rtc_security_iv_prefix_length))
		return false;
	if (!config_check_keys(
		    "Rta", app_config.rta_security_mode, app_config.rta_security_algorithm,
		    app_config.rta_security_key_length, app_config.rta_security_iv_prefix_length))
		return false;

	return true;
}

void config_free(void)
{
	if (app_config.application_xdp_program)
		free(app_config.application_xdp_program);

	if (app_config.tsn_high_payload_pattern)
		free(app_config.tsn_high_payload_pattern);
	if (app_config.tsn_high_security_key)
		free(app_config.tsn_high_security_key);
	if (app_config.tsn_high_security_iv_prefix)
		free(app_config.tsn_high_security_iv_prefix);

	if (app_config.tsn_low_payload_pattern)
		free(app_config.tsn_low_payload_pattern);
	if (app_config.tsn_low_security_key)
		free(app_config.tsn_low_security_key);
	if (app_config.tsn_low_security_iv_prefix)
		free(app_config.tsn_low_security_iv_prefix);

	if (app_config.rtc_payload_pattern)
		free(app_config.rtc_payload_pattern);
	if (app_config.rtc_security_key)
		free(app_config.rtc_security_key);
	if (app_config.rtc_security_iv_prefix)
		free(app_config.rtc_security_iv_prefix);

	if (app_config.rta_payload_pattern)
		free(app_config.rta_payload_pattern);
	if (app_config.rta_security_key)
		free(app_config.rta_security_key);
	if (app_config.rta_security_iv_prefix)
		free(app_config.rta_security_iv_prefix);

	if (app_config.dcp_payload_pattern)
		free(app_config.dcp_payload_pattern);

	if (app_config.lldp_payload_pattern)
		free(app_config.lldp_payload_pattern);

	if (app_config.udp_high_payload_pattern)
		free(app_config.udp_high_payload_pattern);
	if (app_config.udp_high_port)
		free(app_config.udp_high_port);
	if (app_config.udp_high_destination)
		free(app_config.udp_high_destination);
	if (app_config.udp_high_source)
		free(app_config.udp_high_source);

	if (app_config.udp_low_payload_pattern)
		free(app_config.udp_low_payload_pattern);
	if (app_config.udp_low_port)
		free(app_config.udp_low_port);
	if (app_config.udp_low_destination)
		free(app_config.udp_low_destination);
	if (app_config.udp_low_source)
		free(app_config.udp_low_source);

	if (app_config.generic_l2_name)
		free(app_config.generic_l2_name);
	if (app_config.generic_l2_payload_pattern)
		free(app_config.generic_l2_payload_pattern);

	if (app_config.log_file)
		free(app_config.log_file);
	if (app_config.log_level)
		free(app_config.log_level);

	if (app_config.log_via_mqtt_broker_ip)
		free(app_config.log_via_mqtt_broker_ip);
	if (app_config.log_via_mqtt_measurement_name)
		free(app_config.log_via_mqtt_measurement_name);
}
