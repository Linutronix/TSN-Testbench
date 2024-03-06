// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include "tx_time.h"

#include "config.h"
#include "log.h"
#include "utils.h"

uint64_t tx_time_get_frame_duration(uint32_t link_speed, size_t frame_length)
{
	uint64_t duration_ns;

	/* ((frameLength * 8) / (linkSpeed * 1000000ULL)) * 1000000000ULL */
	duration_ns = (frame_length * 8 * 1000) / link_speed;

	return duration_ns;
}

uint64_t tx_time_get_frame_tx_time(uint64_t wakeup_time, uint64_t sequence_counter, uint64_t duration,
			      size_t num_frames_per_cycle, uint64_t tx_time_offset,
			      const char *traffic_class)
{
	const uint64_t tx_thread_offset = app_config.application_tx_base_offset_ns;
	const uint64_t cycle_time = app_config.application_base_cycle_time_ns;
	uint64_t tx_time, base_time, now_ns;
	struct timespec now;

	/*
	 * Calculate frame transmission time for next cycle. txTimeOffset is
	 * used to specify the offset within cycle, which has to be aligned with
	 * configured Qbv schedule.
	 *
	 *   BaseTime + TxOffset +
	 *   (sequenceCounter % numFramesPerCycle) * duration
	 *
	 *   |---------------------------|---------------------------|
	 *   ^BaseTime   ^TxThreadoffset    ^^^^^^
	 *
	 * All calculations are performed in nanoseconds.
	 */

	base_time = wakeup_time - tx_thread_offset + cycle_time;

	tx_time = base_time + tx_time_offset + (sequence_counter % num_frames_per_cycle) * duration;

	/*
	 * TxTime has to be in the future. If not the frame will be dropped by
	 * ETF Qdisc. This may happen due to delays, preemption and so
	 * on. Inform the user accordingly.
	 */
	clock_gettime(app_config.application_clock_id, &now);
	now_ns = ts_to_ns(&now);

	if (tx_time <= now_ns)
		log_message(LOG_LEVEL_ERROR, "%sTx: TxTime not in future!\n", traffic_class);

	return tx_time;
}
