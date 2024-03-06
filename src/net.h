/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _NET_H_
#define _NET_H_

#include <stddef.h>

#include <sys/socket.h>

#include "net_def.h"

int CreateTSNHighSocket(void);
int CreateTSNLowSocket(void);
int CreateRTCSocket(void);
int CreateRTASocket(void);
int CreateDCPSocket(void);
int CreateLLDPSocket(void);
int CreateGenericL2Socket(void);
int CreateUDPSocket(const char *udpDestination, const char *udpSource, const char *udpPort,
		    int socketPriority, struct sockaddr_storage *destination);
int GetInterfaceMacAddress(const char *ifName, unsigned char *mac, size_t len);
int GetInterfaceLinkSpeed(const char *ifName, uint32_t *speed);

#endif /* _NET_H_ */
