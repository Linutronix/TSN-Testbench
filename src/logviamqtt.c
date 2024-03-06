// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024 Intel Corporation.
 * Author Walfred Tedeschi <walfred.tedeschi@intel.com>
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app_config.h"
#ifdef WITH_MQTT
#include <mosquitto.h>
#endif

#include "config.h"
#include "logviamqtt.h"
#include "ring_buffer.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

#define LOGVIAMQTT_BUFFER_SIZE (8 * 1024)

#ifndef WITH_MQTT
struct log_via_mqtt_thread_context *log_via_mqtt_thread_create()
{
	return NULL;
}

void log_via_mqtt_thread_wait_for_finish(struct log_via_mqtt_thread_context *thread_context)
{
}

void log_via_mqtt_stats(enum stat_frame_type frame_type, struct statistics *stats)
{
}

void log_via_mqtt_free()
{
}

#else

static struct ring_buffer *log_via_mqtt_global_log_ring_buffer;

struct log_statistics {
	enum stat_frame_type frame_type;
	uint64_t time_stamp;
	uint64_t frames_sent;
	uint64_t frames_received;
	uint64_t out_of_order_errors;
	uint64_t frame_id_errors;
	uint64_t payload_errors;
	uint64_t round_trip_min;
	uint64_t round_trip_max;
	uint64_t round_trip_outliers;
	double round_trip_avg;
};

int log_via_mqtt_init()
{
	log_via_mqtt_global_log_ring_buffer = ring_buffer_allocate(LOGVIAMQTT_BUFFER_SIZE);
	if (!log_via_mqtt_global_log_ring_buffer)
		return -ENOMEM;

	return 0;
}

void log_via_mqtt_stats(enum stat_frame_type frame_type, struct statistics *stats)
{
	struct log_statistics internal;

	internal.frame_type = frame_type;
	internal.time_stamp = stats->last_time_stamp;
	internal.frames_sent = stats->frames_sent;
	internal.frames_received = stats->frames_received;
	internal.out_of_order_errors = stats->out_of_order_errors;
	internal.frame_id_errors = stats->frame_id_errors;
	internal.payload_errors = stats->payload_errors;
	internal.round_trip_min = stats->round_trip_min;
	internal.round_trip_max = stats->round_trip_max;
	internal.round_trip_outliers = stats->round_trip_outliers;
	internal.round_trip_avg = stats->round_trip_avg;

	ring_buffer_add(log_via_mqtt_global_log_ring_buffer, (const unsigned char *)&internal,
		      sizeof(struct log_statistics));
}

static void log_via_mqtt_add_traffic_class(struct mosquitto *mosq, const char *mqtt_base_topic_name,
				      struct log_statistics *stat)
{
	char stat_message[1024] = {}, *p;
	size_t stat_message_length;
	int written, result_pub;
	uint64_t time_ns;

	stat_message_length = sizeof(stat_message) - 1;
	p = stat_message;

	time_ns = stat->time_stamp;
	written = snprintf(p, stat_message_length,
			   "{\"%s\" :\n"
			   "\t{\"Timestamp\" : %" PRIu64 ",\n"
			   "\t \"MeasurementName\" : \"%s\"",
			   "reference", time_ns, mqtt_base_topic_name);

	p += written;
	stat_message_length -= written;

	written = snprintf(p, stat_message_length,
			   ",\n\t\t\"%s\" : \n\t\t{\n"
			   "\t\t\t\"TCName\" : \"%s\",\n"
			   "\t\t\t\"FramesSent\" : %" PRIu64 ",\n"
			   "\t\t\t\"FramesReceived\" : %" PRIu64 ",\n"
			   "\t\t\t\"RoundTripTime\" : %" PRIu64 ",\n"
			   "\t\t\t\"RoundTripMax\" : %" PRIu64 ",\n"
			   "\t\t\t\"RoundTripAv\" : %lf,\n"
			   "\t\t\t\"OutofOrderErrors\" : %" PRIu64 ",\n"
			   "\t\t\t\"FrameIdErrors\" : %" PRIu64 ",\n"
			   "\t\t\t\"PayloadErrors\" : %" PRIu64 ",\n"
			   "\t\t\t\"RoundTripOutliers\" : %" PRIu64 "\n\t\t}",
			   "stats", stat_frame_type_to_string(stat->frame_type), stat->frames_sent,
			   stat->frames_received, stat->round_trip_min, stat->round_trip_max,
			   stat->round_trip_avg, stat->out_of_order_errors, stat->frame_id_errors,
			   stat->payload_errors, stat->round_trip_outliers);

	p += written;
	stat_message_length -= written;

	written = snprintf(p, stat_message_length, "\t\t\n}\t\n}\n");

	p += written;
	stat_message_length -= written;

	result_pub = mosquitto_publish(mosq, NULL, "testbench", strlen(stat_message), stat_message, 2,
				      false);
	if (result_pub != MOSQ_ERR_SUCCESS)
		fprintf(stderr, "Error publishing: %s\n", mosquitto_strerror(result_pub));
}

static void log_via_mqtt_on_connect(struct mosquitto *mosq, void *obj, int reason_code)
{
	if (reason_code != 0)
		mosquitto_disconnect(mosq);
}

static void *log_via_mqtt_thread_routine(void *data)
{
	uint64_t period_ns = app_config.log_via_mqtt_thread_period_ns;
	struct log_via_mqtt_thread_context *mqtt_context = data;
	struct log_statistics stats[10 * NUM_FRAME_TYPES];
	int ret, connect_status;
	struct timespec time;
	size_t log_data_len;

	mosquitto_lib_init();

	mqtt_context->mosq = mosquitto_new(NULL, true, NULL);
	if (mqtt_context->mosq == NULL) {
		fprintf(stderr, "MQTTLog Error: Out of memory.\n");
		goto err_mqtt_outof_memory;
	}

	connect_status = mosquitto_connect(mqtt_context->mosq, app_config.log_via_mqtt_broker_ip,
					  app_config.log_via_mqtt_broker_port,
					  app_config.log_via_mqtt_keep_alive_secs);
	if (connect_status != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "MQTTLog Error by connect: %s\n",
			mosquitto_strerror(connect_status));
		goto err_mqtt_connect;
	}

	mosquitto_connect_callback_set(mqtt_context->mosq, log_via_mqtt_on_connect);

	ret = mosquitto_loop_start(mqtt_context->mosq);
	if (ret != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "Log Via MQTT Error: %s\n", mosquitto_strerror(ret));
		goto err_mqtt_start;
	}

	/*
	 * Send the statistics periodically to the MQTT broker.  This thread can run with low
	 * priority to not influence to Application Tasks that much.
	 */
	ret = clock_gettime(app_config.application_clock_id, &time);
	if (ret) {
		fprintf(stderr, "Log Via MQTT: clock_gettime() failed: %s!", strerror(errno));
		goto err_time;
	}

	while (!mqtt_context->stop) {
		struct log_statistics *curr_stats;
		int nof_read_elements;

		increment_period(&time, period_ns);
		ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME, &time, NULL);
		if (ret) {
			pthread_error(ret, "clock_nanosleep() failed");
			goto err_time;
		}

		ring_buffer_fetch(mqtt_context->mqtt_log_ring_buffer, (unsigned char *)&stats,
				sizeof(stats), &log_data_len);
		nof_read_elements = log_data_len / sizeof(struct log_statistics);

		curr_stats = (struct log_statistics *)stats;
		for (int i = 0; i < nof_read_elements; i++)
			log_via_mqtt_add_traffic_class(mqtt_context->mosq,
						  app_config.log_via_mqtt_measurement_name,
						  &curr_stats[i]);
	}

	return NULL;

err_mqtt_outof_memory:
err_mqtt_connect:
err_mqtt_start:
err_time:
	if (mqtt_context->mosq)
		mosquitto_destroy(mqtt_context->mosq);
	mosquitto_lib_cleanup();
	return NULL;
}

struct log_via_mqtt_thread_context *log_via_mqtt_thread_create(void)
{
	struct log_via_mqtt_thread_context *mqtt_context;
	int init_val, ret = 0;

	if (!app_config.log_via_mqtt)
		return NULL;

	mqtt_context = malloc(sizeof(*mqtt_context));
	if (!mqtt_context)
		return NULL;

	memset(mqtt_context, '\0', sizeof(*mqtt_context));

	init_val = log_via_mqtt_init();
	if (init_val != 0)
		goto err_thread;

	mqtt_context->mqtt_log_ring_buffer = log_via_mqtt_global_log_ring_buffer;

	ret = create_rt_thread(&mqtt_context->mqtt_log_task_id, "LoggerGraph",
			     app_config.log_via_mqtt_thread_priority, app_config.log_via_mqtt_thread_cpu,
			     log_via_mqtt_thread_routine, mqtt_context);

	if (ret)
		goto err_thread;

	return mqtt_context;

err_thread:
	free(mqtt_context);
	return NULL;
}

void log_via_mqtt_thread_free(struct log_via_mqtt_thread_context *thread_context)
{
	if (!thread_context)
		return;

	if (app_config.log_via_mqtt) {
		if (thread_context->mosq)
			mosquitto_destroy(thread_context->mosq);
		mosquitto_lib_cleanup();
	}

	free(thread_context);
}

void log_via_mqtt_thread_stop(struct log_via_mqtt_thread_context *thread_context)
{
	if (!thread_context)
		return;

	thread_context->stop = 1;
	pthread_join(thread_context->mqtt_log_task_id, NULL);
}

void log_via_mqtt_free()
{
	ring_buffer_free(log_via_mqtt_global_log_ring_buffer);
}

void log_via_mqtt_thread_wait_for_finish(struct log_via_mqtt_thread_context *thread_context)
{
	if (!thread_context)
		return;

	pthread_join(thread_context->mqtt_log_task_id, NULL);
}
#endif
