// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020,2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "thread.h"
#include "utils.h"

int CreateRtThread(pthread_t *taskId, const char *threadName, int threadPriority, int cpuCore,
		   void *(*threadRoutine)(void *), void *data)
{
	struct sched_param param;
	pthread_attr_t attr;
	cpu_set_t cpus;
	int ret;

	ret = pthread_attr_init(&attr);
	if (ret) {
		PthreadError(ret, "pthread_attr_init() failed");
		goto err;
	}

	/* 2 MiB stack should be enough for all threads. */
	ret = pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
	if (ret) {
		PthreadError(ret, "pthread_attr_setstacksize() failed");
		goto err;
	}

	ret = pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
	if (ret) {
		PthreadError(ret, "pthread_attr_setschedpolicy() failed");
		goto err;
	}

	param.sched_priority = threadPriority;
	ret = pthread_attr_setschedparam(&attr, &param);
	if (ret) {
		PthreadError(ret, "pthread_attr_setschedparam() failed");
		goto err;
	}

	ret = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
	if (ret) {
		PthreadError(ret, "pthread_attr_setinheritsched() failed");
		goto err;
	}

	CPU_ZERO(&cpus);
	CPU_SET(cpuCore, &cpus);
	ret = pthread_attr_setaffinity_np(&attr, sizeof(cpus), &cpus);
	if (ret) {
		PthreadError(ret, "pthread_attr_setaffinity_np() failed");
		goto err;
	}

	ret = pthread_create(taskId, &attr, threadRoutine, data);
	if (ret) {
		PthreadError(ret, "pthread_create() failed");
		goto err;
	}

	pthread_setname_np(*taskId, threadName);

	return 0;

err:
	return -ret;
}

void InitMutex(pthread_mutex_t *mutex)
{
	pthread_mutexattr_t mattr;

	/*
	 * Set priority inheritance protocol on this mutex. It's disabled by
	 * default.
	 */
	pthread_mutexattr_init(&mattr);
	pthread_mutexattr_setprotocol(&mattr, PTHREAD_PRIO_INHERIT);
	pthread_mutex_init(mutex, &mattr);
}

void InitConditionVariable(pthread_cond_t *condVar)
{
	pthread_cond_init(condVar, NULL);
}

static struct ThreadContext *FindNextPNThread(struct ThreadContext *pnThreads, int start)
{
	switch (start) {
	case TSN_HIGH_THREAD:
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(TsnLow))
			return &pnThreads[TSN_LOW_THREAD];
	case TSN_LOW_THREAD:
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Rtc))
			return &pnThreads[RTC_THREAD];
	case RTC_THREAD:
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Rta))
			return &pnThreads[RTA_THREAD];
	case RTA_THREAD:
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Dcp))
			return &pnThreads[DCP_THREAD];
	case DCP_THREAD:
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Lldp))
			return &pnThreads[LLDP_THREAD];
	case LLDP_THREAD:
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(UdpHigh))
			return &pnThreads[UDP_HIGH_THREAD];
	case UDP_HIGH_THREAD:
		if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(UdpLow))
			return &pnThreads[UDP_LOW_THREAD];
	case UDP_LOW_THREAD:
		return NULL;
	}

	return NULL;
}

int LinkPNThreads(struct ThreadContext *pnThreads)
{
	/*
	 * The Profinet traffic classes have a dedicated order:
	 *   TSN -> RTC -> RTA -> DCP -> LLDP -> UDP
	 *
	 * This code will link the traffic classes in order. Non-active traffic classes will be
	 * skipped.
	 */
	for (int i = 0; i < NUM_PN_THREAD_TYPES; i++) {
		struct ThreadContext *current = &pnThreads[i];

		current->Next = FindNextPNThread(pnThreads, i);
	}

	/*
	 * The first traffic class is either
	 *  a) TSN in case of Profinet TSN, or
	 *  b) RTC in case of Profinet RT.
	 *
	 * GenericL2 has nothing todo with Profinet.
	 */
	if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(TsnHigh))
		pnThreads[TSN_HIGH_THREAD].IsFirst = true;
	else if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Rtc))
		pnThreads[RTC_THREAD].IsFirst = true;
	else if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(GenericL2))
		return 0;
	else
		return -EINVAL;

	return 0;
}
