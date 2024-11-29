/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef HIST_H
#define HIST_H

#include <stdint.h>

#include "stat.h"

struct histogram {
	uint64_t *data;
	uint64_t min;
	uint64_t max;
	uint64_t underflow;
	uint64_t overflow;
};

int histogram_init(void);
void histogram_free(void);
void histogram_update(enum stat_frame_type frame_type, uint64_t rtt);
int histogram_write(void);

#endif /* HIST_H */
