/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "app_config.h"

#include "security.h"

struct application_config {
	/* Application scheduling configuration */
	clockid_t application_clock_id;
	uint64_t application_base_cycle_time_ns;
	uint64_t application_base_start_time_ns;
	uint64_t application_tx_base_offset_ns;
	uint64_t application_rx_base_offset_ns;
	char *application_xdp_program;
	size_t application_xdp_program_length;
	/* TSN High */
	bool tsn_high_enabled;
	bool tsn_high_rx_mirror_enabled;
	bool tsn_high_xdp_enabled;
	bool tsn_high_xdp_skb_mode;
	bool tsn_high_xdp_zc_mode;
	bool tsn_high_xdp_wakeup_mode;
	bool tsn_high_xdp_busy_poll_mode;
	bool tsn_high_tx_time_enabled;
	bool tsn_high_ignore_rx_errors;
	uint64_t tsn_high_tx_time_offset_ns;
	int tsn_high_vid;
	size_t tsn_high_num_frames_per_cycle;
	char *tsn_high_payload_pattern;
	size_t tsn_high_payload_pattern_length;
	size_t tsn_high_frame_length;
	enum security_mode tsn_high_security_mode;
	enum security_algorithm tsn_high_security_algorithm;
	char *tsn_high_security_key;
	size_t tsn_high_security_key_length;
	char *tsn_high_security_iv_prefix;
	size_t tsn_high_security_iv_prefix_length;
	int tsn_high_rx_queue;
	int tsn_high_tx_queue;
	int tsn_high_socket_priority;
	int tsn_high_tx_thread_priority;
	int tsn_high_rx_thread_priority;
	int tsn_high_tx_thread_cpu;
	int tsn_high_rx_thread_cpu;
	char tsn_high_interface[IF_NAMESIZE];
	unsigned char tsn_high_destination[ETH_ALEN];
	/* TSN Low */
	bool tsn_low_enabled;
	bool tsn_low_rx_mirror_enabled;
	bool tsn_low_xdp_enabled;
	bool tsn_low_xdp_skb_mode;
	bool tsn_low_xdp_zc_mode;
	bool tsn_low_xdp_wakeup_mode;
	bool tsn_low_xdp_busy_poll_mode;
	bool tsn_low_tx_time_enabled;
	bool tsn_low_ignore_rx_errors;
	uint64_t tsn_low_tx_time_offset_ns;
	int tsn_low_vid;
	size_t tsn_low_num_frames_per_cycle;
	char *tsn_low_payload_pattern;
	size_t tsn_low_payload_pattern_length;
	size_t tsn_low_frame_length;
	enum security_mode tsn_low_security_mode;
	enum security_algorithm tsn_low_security_algorithm;
	char *tsn_low_security_key;
	size_t tsn_low_security_key_length;
	char *tsn_low_security_iv_prefix;
	size_t tsn_low_security_iv_prefix_length;
	int tsn_low_rx_queue;
	int tsn_low_tx_queue;
	int tsn_low_socket_priority;
	int tsn_low_tx_thread_priority;
	int tsn_low_rx_thread_priority;
	int tsn_low_tx_thread_cpu;
	int tsn_low_rx_thread_cpu;
	char tsn_low_interface[IF_NAMESIZE];
	unsigned char tsn_low_destination[ETH_ALEN];
	/* Real Time Cyclic (RTC) */
	bool rtc_enabled;
	bool rtc_rx_mirror_enabled;
	bool rtc_xdp_enabled;
	bool rtc_xdp_skb_mode;
	bool rtc_xdp_zc_mode;
	bool rtc_xdp_wakeup_mode;
	bool rtc_xdp_busy_poll_mode;
	bool rtc_ignore_rx_errors;
	int rtc_vid;
	size_t rtc_num_frames_per_cycle;
	char *rtc_payload_pattern;
	size_t rtc_payload_pattern_length;
	size_t rtc_frame_length;
	enum security_mode rtc_security_mode;
	enum security_algorithm rtc_security_algorithm;
	char *rtc_security_key;
	size_t rtc_security_key_length;
	char *rtc_security_iv_prefix;
	size_t rtc_security_iv_prefix_length;
	int rtc_rx_queue;
	int rtc_tx_queue;
	int rtc_socket_priority;
	int rtc_tx_thread_priority;
	int rtc_rx_thread_priority;
	int rtc_tx_thread_cpu;
	int rtc_rx_thread_cpu;
	char rtc_interface[IF_NAMESIZE];
	unsigned char rtc_destination[ETH_ALEN];
	/* Real Time Acyclic (RTA) */
	bool rta_enabled;
	bool rta_rx_mirror_enabled;
	bool rta_xdp_enabled;
	bool rta_xdp_skb_mode;
	bool rta_xdp_zc_mode;
	bool rta_xdp_wakeup_mode;
	bool rta_xdp_busy_poll_mode;
	bool rta_ignore_rx_errors;
	int rta_vid;
	uint64_t rta_burst_period_ns;
	size_t rta_num_frames_per_cycle;
	char *rta_payload_pattern;
	size_t rta_payload_pattern_length;
	size_t rta_frame_length;
	enum security_mode rta_security_mode;
	enum security_algorithm rta_security_algorithm;
	char *rta_security_key;
	size_t rta_security_key_length;
	char *rta_security_iv_prefix;
	size_t rta_security_iv_prefix_length;
	int rta_rx_queue;
	int rta_tx_queue;
	int rta_socket_priority;
	int rta_tx_thread_priority;
	int rta_rx_thread_priority;
	int rta_tx_thread_cpu;
	int rta_rx_thread_cpu;
	char rta_interface[IF_NAMESIZE];
	unsigned char rta_destination[ETH_ALEN];
	/* Discovery and Configuration Protocol (DCP) */
	bool dcp_enabled;
	bool dcp_rx_mirror_enabled;
	bool dcp_ignore_rx_errors;
	int dcp_vid;
	uint64_t dcp_burst_period_ns;
	size_t dcp_num_frames_per_cycle;
	char *dcp_payload_pattern;
	size_t dcp_payload_pattern_length;
	size_t dcp_frame_length;
	int dcp_rx_queue;
	int dcp_tx_queue;
	int dcp_socket_priority;
	int dcp_tx_thread_priority;
	int dcp_rx_thread_priority;
	int dcp_tx_thread_cpu;
	int dcp_rx_thread_cpu;
	char dcp_interface[IF_NAMESIZE];
	unsigned char dcp_destination[ETH_ALEN];
	/* Link Layer Discovery Protocol (LLDP) */
	bool lldp_enabled;
	bool lldp_rx_mirror_enabled;
	bool lldp_ignore_rx_errors;
	uint64_t lldp_burst_period_ns;
	size_t lldp_num_frames_per_cycle;
	char *lldp_payload_pattern;
	size_t lldp_payload_pattern_length;
	size_t lldp_frame_length;
	int lldp_rx_queue;
	int lldp_tx_queue;
	int lldp_socket_priority;
	int lldp_tx_thread_priority;
	int lldp_rx_thread_priority;
	int lldp_tx_thread_cpu;
	int lldp_rx_thread_cpu;
	char lldp_interface[IF_NAMESIZE];
	unsigned char lldp_destination[ETH_ALEN];
	/* User Datagram Protocol (UDP) High */
	bool udp_high_enabled;
	bool udp_high_rx_mirror_enabled;
	bool udp_high_ignore_rx_errors;
	uint64_t udp_high_burst_period_ns;
	size_t udp_high_num_frames_per_cycle;
	char *udp_high_payload_pattern;
	size_t udp_high_payload_pattern_length;
	size_t udp_high_frame_length;
	int udp_high_rx_queue;
	int udp_high_tx_queue;
	int udp_high_socket_priority;
	int udp_high_tx_thread_priority;
	int udp_high_rx_thread_priority;
	int udp_high_tx_thread_cpu;
	int udp_high_rx_thread_cpu;
	char udp_high_interface[IF_NAMESIZE];
	char *udp_high_port;
	size_t udp_high_port_length;
	char *udp_high_destination;
	size_t udp_high_destination_length;
	char *udp_high_source;
	size_t udp_high_source_length;
	/* User Datagram Protocol (UDP) Low */
	bool udp_low_enabled;
	bool udp_low_rx_mirror_enabled;
	bool udp_low_ignore_rx_errors;
	uint64_t udp_low_burst_period_ns;
	size_t udp_low_num_frames_per_cycle;
	char *udp_low_payload_pattern;
	size_t udp_low_payload_pattern_length;
	size_t udp_low_frame_length;
	int udp_low_rx_queue;
	int udp_low_tx_queue;
	int udp_low_socket_priority;
	int udp_low_tx_thread_priority;
	int udp_low_rx_thread_priority;
	int udp_low_tx_thread_cpu;
	int udp_low_rx_thread_cpu;
	char udp_low_interface[IF_NAMESIZE];
	char *udp_low_port;
	size_t udp_low_port_length;
	char *udp_low_destination;
	size_t udp_low_destination_length;
	char *udp_low_source;
	size_t udp_low_source_length;
	/* Generic Layer 2 (example: OPC/UA PubSub) */
	char *generic_l2_name;
	size_t generic_l2_name_length;
	bool generic_l2_enabled;
	bool generic_l2_rx_mirror_enabled;
	bool generic_l2_xdp_enabled;
	bool generic_l2_xdp_skb_mode;
	bool generic_l2_xdp_zc_mode;
	bool generic_l2_xdp_wakeup_mode;
	bool generic_l2_xdp_busy_poll_mode;
	bool generic_l2_tx_time_enabled;
	bool generic_l2_ignore_rx_errors;
	uint64_t generic_l2_tx_time_offset_ns;
	int generic_l2_vid;
	int generic_l2_pcp;
	unsigned int generic_l2_ether_type;
	size_t generic_l2_num_frames_per_cycle;
	char *generic_l2_payload_pattern;
	size_t generic_l2_payload_pattern_length;
	size_t generic_l2_frame_length;
	int generic_l2_rx_queue;
	int generic_l2_tx_queue;
	int generic_l2_socket_priority;
	int generic_l2_tx_thread_priority;
	int generic_l2_rx_thread_priority;
	int generic_l2_tx_thread_cpu;
	int generic_l2_rx_thread_cpu;
	char generic_l2_interface[IF_NAMESIZE];
	unsigned char generic_l2_destination[ETH_ALEN];
	/* Logging */
	uint64_t log_thread_period_ns;
	int log_thread_priority;
	int log_thread_cpu;
	char *log_file;
	size_t log_file_length;
	char *log_level;
	size_t log_level_length;
	/* Debug */
	bool debug_stop_trace_on_rtt;
	bool debug_stop_trace_on_error;
	uint64_t debug_stop_trace_rtt_limit_ns;
	bool debug_monitor_mode;
	unsigned char debug_monitor_destination[ETH_ALEN];
	/* Statistics */
	uint64_t stats_collection_interval_ns;
	/* Log through MQTT */
	bool log_via_mqtt;
	int log_via_mqtt_thread_priority;
	int log_via_mqtt_thread_cpu;
	uint64_t log_via_mqtt_thread_period_ns;
	size_t log_via_mqtt_broker_ip_length;
	char *log_via_mqtt_broker_ip;
	int log_via_mqtt_broker_port;
	int log_via_mqtt_keep_alive_secs;
	size_t log_via_mqtt_measurement_name_length;
	char *log_via_mqtt_measurement_name;
};

extern struct application_config app_config;

int config_read_from_file(const char *config_file);
int config_set_defaults(bool mirror_enabled);
void config_print_values(void);
bool config_sanity_check(void);
void config_free(void);

#define CONFIG_STORE_BOOL_PARAM(name)                                                              \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			if (!strcmp(value, "0") || !strcasecmp(value, "false"))                    \
				app_config.name = false;                                           \
			else if (!strcmp(value, "1") || !strcasecmp(value, "true"))                \
				app_config.name = true;                                            \
			else {                                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_INT_PARAM(name)                                                               \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			app_config.name = strtol(value, &endptr, 10);                              \
			if (errno != 0 || endptr == value || *endptr != '\0') {                    \
				ret = -ERANGE;                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_ULONG_PARAM(name)                                                             \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			app_config.name = strtoull(value, &endptr, 10);                            \
			if (errno != 0 || endptr == value || *endptr != '\0') {                    \
				ret = -ERANGE;                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_STRING_PARAM(name)                                                            \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			app_config.name = strdup(value);                                           \
			if (!app_config.name) {                                                    \
				ret = -ENOMEM;                                                     \
				fprintf(stderr, "strdup() for " #name " failed!\n");               \
				goto err_parse;                                                    \
			}                                                                          \
			app_config.name##_length = strlen(value);                                  \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_INTERFACE_PARAM(name)                                                         \
	do {                                                                                       \
		if (!strcmp(key, #name))                                                           \
			strncpy(app_config.name, value, sizeof(app_config.name) - 1);              \
	} while (0)

#define CONFIG_STORE_MAC_PARAM(name)                                                               \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			unsigned int tmp[ETH_ALEN];                                                \
			int i;                                                                     \
                                                                                                   \
			ret = sscanf(value, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2],        \
				     &tmp[3], &tmp[4], &tmp[5]);                                   \
                                                                                                   \
			if (ret != ETH_ALEN) {                                                     \
				fprintf(stderr, "Failed to parse MAC Address!\n");                 \
				ret = -EINVAL;                                                     \
				goto err_parse;                                                    \
			}                                                                          \
                                                                                                   \
			for (i = 0; i < ETH_ALEN; ++i)                                             \
				app_config.name[i] = (unsigned char)tmp[i];                        \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_CLOCKID_PARAM(name)                                                           \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			if (strcmp(value, "CLOCK_TAI") && strcmp(value, "CLOCK_MONOTONIC")) {      \
				fprintf(stderr, "Invalid clockid specified!\n");                   \
				goto err_parse;                                                    \
			}                                                                          \
                                                                                                   \
			if (!strcmp(value, "CLOCK_TAI"))                                           \
				app_config.name = CLOCK_TAI;                                       \
			if (!strcmp(value, "CLOCK_MONOTONIC"))                                     \
				app_config.name = CLOCK_MONOTONIC;                                 \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_ETHER_TYPE(name)                                                              \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			app_config.name = strtoul(value, &endptr, 16);                             \
			if (errno != 0 || endptr == value || *endptr != '\0') {                    \
				ret = -ERANGE;                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_SECURITY_MODE_PARAM(name)                                                     \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			if (strcasecmp(value, "none") && strcasecmp(value, "ao") &&                \
			    strcasecmp(value, "ae")) {                                             \
				fprintf(stderr, "Invalid security mode specified!\n");             \
				goto err_parse;                                                    \
			}                                                                          \
                                                                                                   \
			if (!strcasecmp(value, "none"))                                            \
				app_config.name = SECURITY_MODE_NONE;                              \
			if (!strcasecmp(value, "ao"))                                              \
				app_config.name = SECURITY_MODE_AO;                                \
			if (!strcasecmp(value, "ae"))                                              \
				app_config.name = SECURITY_MODE_AE;                                \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_SECURITY_ALGORITHM_PARAM(name)                                                \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			if (strcasecmp(value, "aes256-gcm") && strcasecmp(value, "aes128-gcm") &&  \
			    strcasecmp(value, "chacha20-poly1305")) {                              \
				fprintf(stderr, "Invalid security algorithm specified!\n");        \
				goto err_parse;                                                    \
			}                                                                          \
			if (!strcasecmp(value, "aes256-gcm"))                                      \
				app_config.name = SECURITY_ALGORITHM_AES256_GCM;                   \
			if (!strcasecmp(value, "aes128-gcm"))                                      \
				app_config.name = SECURITY_ALGORITHM_AES128_GCM;                   \
			if (!strcasecmp(value, "chacha20-poly1305"))                               \
				app_config.name = SECURITY_ALGORITHM_CHACHA20_POLY1305;            \
		}                                                                                  \
	} while (0)

#define CONFIG_IS_TRAFFIC_CLASS_ACTIVE(name)                                                       \
	({                                                                                         \
		bool __ret = false;                                                                \
		if (app_config.name##_enabled && app_config.name##_num_frames_per_cycle > 0)       \
			__ret = true;                                                              \
		__ret;                                                                             \
	})

static inline bool config_have_busy_poll(void)
{
#if defined(HAVE_SO_BUSY_POLL) && defined(HAVE_SO_PREFER_BUSY_POLL) &&                             \
	defined(HAVE_SO_BUSY_POLL_BUDGET)
	return true;
#else
	return false;
#endif
}

static inline bool config_have_mosquitto(void)
{
#if defined(WITH_MQTT)
	return true;
#else
	return false;
#endif
}

#endif /* _CONFIG_H_ */
