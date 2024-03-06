/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _TX_TIME_H_
#define _TX_TIME_H_

#include <stddef.h>
#include <stdint.h>

uint64_t tx_time_get_frame_duration(uint32_t link_speed, size_t frame_length);

uint64_t tx_time_get_frame_tx_time(uint64_t wakeup_time, uint64_t sequence_counter,
				   uint64_t duration, size_t num_frames_per_cycle,
				   uint64_t tx_time_offset, const char *traffic_class);

#endif /* _TX_TIME_H_ */
