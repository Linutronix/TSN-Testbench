// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hist.h"

#include "config.h"
#include "stat.h"

static struct histogram histograms[NUM_FRAME_TYPES];

int histogram_init(void)
{
	int i;

	if (!app_config.stats_histogram_enabled)
		return 0;

	for (i = 0; i < NUM_FRAME_TYPES; i++) {
		struct histogram *hist = &histograms[i];

		hist->min = app_config.stats_histogram_mininum_ns;
		hist->max = app_config.stats_histogram_maximum_ns;

		/* RTT is recorded in us */
		hist->min /= 1000;
		hist->max /= 1000;

		hist->data = calloc(hist->max - hist->min, sizeof(uint64_t));
		if (!hist->data)
			return -ENOMEM;
	}

	return 0;
}

void histogram_free(void)
{
	int i;

	if (!app_config.stats_histogram_enabled)
		return;

	for (i = 0; i < NUM_FRAME_TYPES; i++) {
		struct histogram *hist = &histograms[i];

		free(hist->data);
	}
}

void histogram_update(enum stat_frame_type frame_type, uint64_t rtt)
{
	struct histogram *hist = &histograms[frame_type];
	uint64_t sample = rtt - hist->min;

	/* Overflow */
	if (rtt >= hist->max) {
		hist->overflow++;
		return;
	}

	/* Underflow */
	if (rtt < hist->min) {
		hist->underflow++;
		return;
	}

	/* Update sample */
	hist->data[sample]++;
}

/*
 * Write histogram to disk in form like this:
 *   RTT HistMin + 0: TsnHighSampleCount TsnLowSampleCount ...
 *   RTT HistMin + 1: TsnHighSampleCount TsnLowSampleCount ...
 *   [...]
 *   RTT HistMax - 1: TsnHighSampleCount TsnLowSampleCount ...
 */
int histogram_write(void)
{
	uint64_t rtt;
	FILE *f;
	int i;

	if (!app_config.stats_histogram_enabled)
		return 0;

	f = fopen(app_config.stats_histogram_file, "w");
	if (!f) {
		fprintf(stderr, "Failed to open file '%s': %s!\n", app_config.stats_histogram_file,
			strerror(errno));
		return -EINVAL;
	}

	fprintf(f, "Testbench RTT Histogram: %s %s %s %s %s %s %s %s %s\n",
		stat_frame_type_to_string(TSN_HIGH_FRAME_TYPE),
		stat_frame_type_to_string(TSN_LOW_FRAME_TYPE),
		stat_frame_type_to_string(RTC_FRAME_TYPE),
		stat_frame_type_to_string(RTA_FRAME_TYPE),
		stat_frame_type_to_string(DCP_FRAME_TYPE),
		stat_frame_type_to_string(LLDP_FRAME_TYPE),
		stat_frame_type_to_string(UDP_HIGH_FRAME_TYPE),
		stat_frame_type_to_string(UDP_LOW_FRAME_TYPE),
		stat_frame_type_to_string(GENERICL2_FRAME_TYPE));
	for (rtt = histograms[0].min; rtt < histograms[0].max; rtt++) {
		bool print = false;

		for (i = 0; i < NUM_FRAME_TYPES; i++) {
			struct histogram *hist = &histograms[i];

			if (hist->data[rtt - hist->min]) {
				print = true;
				break;
			}
		}

		if (!print)
			continue;

		fprintf(f, "%08" PRIu64 ": ", rtt);
		for (i = 0; i < NUM_FRAME_TYPES; i++) {
			struct histogram *hist = &histograms[i];

			fprintf(f, "%08" PRIu64 "  ", hist->data[rtt - hist->min]);
		}
		fprintf(f, "\n");
	}

	fprintf(f, "Overflow: ");
	for (i = 0; i < NUM_FRAME_TYPES; i++) {
		struct histogram *hist = &histograms[i];

		fprintf(f, "%08" PRIu64 "  ", hist->overflow);
	}
	fprintf(f, "\n");

	fprintf(f, "Underflow: ");
	for (i = 0; i < NUM_FRAME_TYPES; i++) {
		struct histogram *hist = &histograms[i];

		fprintf(f, "%08" PRIu64 "  ", hist->underflow);
	}
	fprintf(f, "\n");

	fclose(f);

	return 0;
}
