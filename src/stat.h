/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _STAT_H_
#define _STAT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum log_stat_options {
	LOG_REFERENCE = 0,
	LOG_MIRROR,
	LOG_NUM_OPTIONS
};

enum stat_frame_type {
	TSN_HIGH_FRAME_TYPE = 0,
	TSN_LOW_FRAME_TYPE,
	RTC_FRAME_TYPE,
	RTA_FRAME_TYPE,
	DCP_FRAME_TYPE,
	LLDP_FRAME_TYPE,
	UDP_HIGH_FRAME_TYPE,
	UDP_LOW_FRAME_TYPE,
	GENERICL2_FRAME_TYPE,
	NUM_FRAME_TYPES,
};

static inline bool stat_frame_type_is_real_time(enum stat_frame_type frame_type)
{
	switch (frame_type) {
	case TSN_HIGH_FRAME_TYPE:
	case TSN_LOW_FRAME_TYPE:
	case RTC_FRAME_TYPE:
	case GENERICL2_FRAME_TYPE:
		return true;
	default:
		return false;
	}
}

extern const char *stat_frame_type_names[NUM_FRAME_TYPES];

static inline const char *stat_frame_type_to_string(enum stat_frame_type frame_type)
{
	return stat_frame_type_names[frame_type];
}

struct statistics {
	uint64_t first_time_stamp;
	uint64_t last_time_stamp;
	uint64_t frames_sent;
	uint64_t frames_received;
	uint64_t out_of_order_errors;
	uint64_t frame_id_errors;
	uint64_t payload_errors;
	uint64_t round_trip_min;
	uint64_t round_trip_max;
	uint64_t round_trip_count;
	uint64_t round_trip_outliers;
	double round_trip_sum;
	double round_trip_avg;
	uint64_t oneway_min;
	uint64_t oneway_max;
	uint64_t oneway_count;
	uint64_t oneway_outliers;
	double oneway_sum;
	double oneway_avg;
	bool ready;
};

extern struct statistics global_statistics[NUM_FRAME_TYPES];
extern struct statistics global_statistics_per_period[NUM_FRAME_TYPES];

struct round_trip_context {
	int64_t *backlog;
	size_t backlog_len;
};
extern struct round_trip_context round_trip_contexts[NUM_FRAME_TYPES];

int stat_init(enum log_stat_options log_selection);
void stat_free(void);
const char *stat_frame_type_to_string(enum stat_frame_type frame_type);
void stat_frame_sent(enum stat_frame_type frame_type, uint64_t cycle_number);
void stat_frame_received(enum stat_frame_type frame_type, uint64_t cycle_number, bool out_of_order,
			 bool payload_mismatch, bool frame_id_mismatch, uint64_t tx_timestamp);

#endif /* _STAT_H_ */
