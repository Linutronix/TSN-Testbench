// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/net.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "config.h"
#include "net.h"
#include "utils.h"

/*
 * Filter for Profinet TSN High Frames:
 *   ldh [12]
 *   jne #0x8892, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ldh [14]
 *   jlt #0x0100, drop
 *   jgt #0x01ff, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter TsnHighFrameFilter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 6, 0x00008892}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 4, 0x00001234}, {0x28, 0, 0, 0x0000000e}, {0x35, 0, 2, 0x00000100},
	{0x25, 1, 0, 0x000001ff}, {0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

/*
 * Filter for Profinet TSN Low Frames:
 *   ldh [12]
 *   jne #0x8892, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ldh [14]
 *   jlt #0x0200, drop
 *   jgt #0x03ff, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter TsnLowFrameFilter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 6, 0x00008892}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 4, 0x00001234}, {0x28, 0, 0, 0x0000000e}, {0x35, 0, 2, 0x00000200},
	{0x25, 1, 0, 0x000003ff}, {0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

/*
 * Filter for Profinet RTC Frames:
 *   ldh [12]
 *   jne #0x8892, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ldh [14]
 *   jlt #0x8000, drop
 *   jgt #0xbbff, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter RtcFrameFilter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 6, 0x00008892}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 4, 0x00001234}, {0x28, 0, 0, 0x0000000e}, {0x35, 0, 2, 0x00008000},
	{0x25, 1, 0, 0x0000bbff}, {0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

/*
 * Filter for Profinet RTA Frames:
 *   ldh [12]
 *   jne #0x8892, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ldh [14]
 *   jne #0xfc01, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter RtaFrameFilter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 5, 0x00008892}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 3, 0x00001234}, {0x28, 0, 0, 0x0000000e}, {0x15, 0, 1, 0x0000fc01},
	{0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

/*
 * Filter for Profinet DCP Frames:
 *   ldh [12]
 *   jne #0x8892, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ldh [14]
 *   jlt #0xfefe, drop
 *   jgt #0xfeff, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter DcpFrameFilter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 6, 0x00008892}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 4, 0x00001234}, {0x28, 0, 0, 0x0000000e}, {0x35, 0, 2, 0x0000fefe},
	{0x25, 1, 0, 0x0000feff}, {0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

/*
 * Filter for LLDP Frames:
 *   ldh [12]
 *   jne #0x88cc, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter LldpFrameFilter[] = {
	{0x28, 0, 0, 0x0000000c},
	{0x15, 0, 1, 0x000088cc},
	{0x06, 0, 0, 0xffffffff},
	{0x06, 0, 0, 0000000000},
};

/*
 * Filter for Generic L2 Frames:
 *   ldh [12]
 *   jne #EtherType, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter GenericL2FrameFilter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 3, 0x00001234}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 1, 0x00004321}, {0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

static int SetPromiscuousMode(int socket, int interface)
{
	struct packet_mreq mreq;
	int ret;

	mreq.mr_ifindex = interface;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 0;

	ret = setsockopt(socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	if (ret) {
		perror("setsockopt() failed");
		return -errno;
	}

	return 0;
}

static int CreateRawSocket(const char *ifName, int socketPriority)
{
	struct sockaddr_ll address = {0};
	int socketFd, interface, ret;

	socketFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (socketFd < 0) {
		perror("socket() failed");
		goto err_socket;
	}

	interface = if_nametoindex(ifName);
	if (!interface) {
		perror("ioctl() failed");
		goto err_index;
	}

	address.sll_ifindex = interface;
	address.sll_family = AF_PACKET;
	address.sll_protocol = htons(ETH_P_ALL);

	ret = bind(socketFd, (struct sockaddr *)&address, sizeof(address));
	if (ret < 0) {
		perror("bind() failed");
		goto err_index;
	}

	ret = setsockopt(socketFd, SOL_SOCKET, SO_BINDTODEVICE, ifName, strlen(ifName));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_index;
	}

	ret = setsockopt(socketFd, SOL_SOCKET, SO_PRIORITY, &socketPriority,
			 sizeof(socketPriority));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_index;
	}

	ret = SetPromiscuousMode(socketFd, interface);
	if (ret)
		goto err_index;

	return socketFd;

err_index:
	close(socketFd);
err_socket:
	return -errno;
}

int GetInterfaceMacAddress(const char *ifName, unsigned char *mac, size_t len)
{
	struct ifreq ifreq = {0};
	int socketFd, ret;

	if (len < ETH_ALEN)
		return -EINVAL;

	strncpy(ifreq.ifr_name, ifName, sizeof(ifreq.ifr_name) - 1);

	socketFd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (socketFd < 0) {
		perror("socket() failed");
		return -errno;
	}

	ret = ioctl(socketFd, SIOCGIFHWADDR, &ifreq);
	close(socketFd);
	if (ret < 0) {
		perror("ioctl() failed");
		return -errno;
	}

	memcpy(mac, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);

	return 0;
}

int GetInterfaceLinkSpeed(const char *ifName, uint32_t *speed)
{
	struct ifreq ifreq = {0};
	struct ethtool_cmd eData;
	int socketFd, ret;

	if (!speed)
		return -EINVAL;

	strncpy(ifreq.ifr_name, ifName, sizeof(ifreq.ifr_name) - 1);
	ifreq.ifr_data = (char *)&eData;

	socketFd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (socketFd < 0) {
		perror("socket() failed");
		return -errno;
	}

	eData.cmd = ETHTOOL_GSET;

	ret = ioctl(socketFd, SIOCETHTOOL, &ifreq);
	close(socketFd);
	if (ret < 0) {
		perror("ioctl() failed");
		return -errno;
	}

	*speed = ethtool_cmd_speed(&eData);

	return 0;
}

int CreateTSNHighSocket(void)
{
	const struct sock_fprog tsnHighFilterProgram = {.len = ARRAY_SIZE(TsnHighFrameFilter),
							.filter = TsnHighFrameFilter};
	struct sock_txtime skTxtime;
	int socketFd, ret;

	socketFd = CreateRawSocket(appConfig.TsnHighInterface, appConfig.TsnHighSocketPriority);
	if (socketFd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Profinet TSN High Frames!\n");
		return socketFd;
	}

	/* Adjust filter: VLAN TCI */
	TsnHighFrameFilter[3].k = appConfig.TsnHighVid | TSN_HIGH_PCP_VALUE << VLAN_PCP_SHIFT;

	ret = setsockopt(socketFd, SOL_SOCKET, SO_ATTACH_FILTER, &tsnHighFilterProgram,
			 sizeof(tsnHighFilterProgram));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	/* Enable SO_TXTIME */
	if (!appConfig.TsnHighTxTimeEnabled)
		goto out;

	skTxtime.clockid = CLOCK_TAI; /* For hardware offload CLOCK_TAI is mandatory */
	skTxtime.flags = 1 << 1;      /* Enable error reporting */
	ret = setsockopt(socketFd, SOL_SOCKET, SO_TXTIME, &skTxtime, sizeof(skTxtime));
	if (ret) {
		perror("setsockopt() failed");
		goto err_filter;
	}

out:
	return socketFd;

err_filter:
	close(socketFd);
	return -errno;
}

int CreateTSNLowSocket(void)
{
	const struct sock_fprog tsnLowFilterProgram = {.len = ARRAY_SIZE(TsnLowFrameFilter),
						       .filter = TsnLowFrameFilter};
	struct sock_txtime skTxtime;
	int socketFd, ret;

	socketFd = CreateRawSocket(appConfig.TsnLowInterface, appConfig.TsnLowSocketPriority);
	if (socketFd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Profinet TSN Low Frames!\n");
		return socketFd;
	}

	/* Adjust filter: VLAN TCI */
	TsnLowFrameFilter[3].k = appConfig.TsnLowVid | TSN_LOW_PCP_VALUE << VLAN_PCP_SHIFT;

	ret = setsockopt(socketFd, SOL_SOCKET, SO_ATTACH_FILTER, &tsnLowFilterProgram,
			 sizeof(tsnLowFilterProgram));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	/* Enable SO_TXTIME */
	if (!appConfig.TsnLowTxTimeEnabled)
		goto out;

	skTxtime.clockid = CLOCK_TAI; /* For hardware offload CLOCK_TAI is mandatory */
	skTxtime.flags = 1 << 1;      /* Enable error reporting */
	ret = setsockopt(socketFd, SOL_SOCKET, SO_TXTIME, &skTxtime, sizeof(skTxtime));
	if (ret) {
		perror("setsockopt() failed");
		goto err_filter;
	}

out:
	return socketFd;

err_filter:
	close(socketFd);
	return -errno;
}

int CreateRTCSocket(void)
{
	const struct sock_fprog rtcFilterProgram = {.len = ARRAY_SIZE(RtcFrameFilter),
						    .filter = RtcFrameFilter};
	int socketFd, ret;

	socketFd = CreateRawSocket(appConfig.RtcInterface, appConfig.RtcSocketPriority);
	if (socketFd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Profinet RTC Frames!\n");
		return socketFd;
	}

	/* Adjust filter: VLAN TCI */
	RtcFrameFilter[3].k = appConfig.RtcVid | RTC_PCP_VALUE << VLAN_PCP_SHIFT;

	ret = setsockopt(socketFd, SOL_SOCKET, SO_ATTACH_FILTER, &rtcFilterProgram,
			 sizeof(rtcFilterProgram));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	return socketFd;

err_filter:
	close(socketFd);
	return -errno;
}

int CreateRTASocket(void)
{
	const struct sock_fprog rtaFilterProgram = {.len = ARRAY_SIZE(RtaFrameFilter),
						    .filter = RtaFrameFilter};
	int socketFd, ret;

	socketFd = CreateRawSocket(appConfig.RtaInterface, appConfig.RtaSocketPriority);
	if (socketFd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Profinet RTC Frames!\n");
		return socketFd;
	}

	/* Adjust filter: VLAN TCI */
	RtaFrameFilter[3].k = appConfig.RtaVid | RTA_PCP_VALUE << VLAN_PCP_SHIFT;

	ret = setsockopt(socketFd, SOL_SOCKET, SO_ATTACH_FILTER, &rtaFilterProgram,
			 sizeof(rtaFilterProgram));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	return socketFd;

err_filter:
	close(socketFd);
	return -errno;
}

int CreateDCPSocket(void)
{
	const struct sock_fprog dcpFilterProgram = {.len = ARRAY_SIZE(DcpFrameFilter),
						    .filter = DcpFrameFilter};
	int socketFd, ret;

	socketFd = CreateRawSocket(appConfig.DcpInterface, appConfig.DcpSocketPriority);
	if (socketFd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Profinet DCP Frames!\n");
		return socketFd;
	}

	/* Adjust filter: VLAN TCI */
	DcpFrameFilter[3].k = appConfig.DcpVid | DCP_PCP_VALUE << VLAN_PCP_SHIFT;

	ret = setsockopt(socketFd, SOL_SOCKET, SO_ATTACH_FILTER, &dcpFilterProgram,
			 sizeof(dcpFilterProgram));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	return socketFd;

err_filter:
	close(socketFd);
	return -errno;
}

int CreateLLDPSocket(void)
{
	const struct sock_fprog lldpFilterProgram = {.len = ARRAY_SIZE(LldpFrameFilter),
						     .filter = LldpFrameFilter};
	int socketFd, ret;

	socketFd = CreateRawSocket(appConfig.LldpInterface, appConfig.LldpSocketPriority);
	if (socketFd < 0) {
		fprintf(stderr, "Failed to create RAW socket for LLDP Frames!\n");
		return socketFd;
	}

	ret = setsockopt(socketFd, SOL_SOCKET, SO_ATTACH_FILTER, &lldpFilterProgram,
			 sizeof(lldpFilterProgram));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	return socketFd;

err_filter:
	close(socketFd);
	return -errno;
}

int CreateGenericL2Socket(void)
{
	const struct sock_fprog genericL2FilterProgram = {.len = ARRAY_SIZE(GenericL2FrameFilter),
							  .filter = GenericL2FrameFilter};
	struct sock_txtime skTxtime;
	int socketFd, ret;

	socketFd = CreateRawSocket(appConfig.GenericL2Interface, appConfig.GenericL2SocketPriority);
	if (socketFd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Generic L2 Frames!\n");
		return socketFd;
	}

	/* Adjust filter: EtherType and VLAN TCI */
	GenericL2FrameFilter[1].k = appConfig.GenericL2EtherType;
	GenericL2FrameFilter[3].k = appConfig.GenericL2Vid | appConfig.GenericL2Pcp
								     << VLAN_PCP_SHIFT;

	ret = setsockopt(socketFd, SOL_SOCKET, SO_ATTACH_FILTER, &genericL2FilterProgram,
			 sizeof(genericL2FilterProgram));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	/* Enable SO_TXTIME */
	if (!appConfig.GenericL2TxTimeEnabled)
		goto out;

	skTxtime.clockid = CLOCK_TAI; /* For hardware offload CLOCK_TAI is mandatory */
	skTxtime.flags = 1 << 1;      /* Enable error reporting */
	ret = setsockopt(socketFd, SOL_SOCKET, SO_TXTIME, &skTxtime, sizeof(skTxtime));
	if (ret) {
		perror("setsockopt() failed");
		goto err_filter;
	}

out:
	return socketFd;

err_filter:
	close(socketFd);
	return -errno;
}

static int DnsLookup(const char *host, const char *port, struct sockaddr_storage *addr,
		     int *socketFd)
{
	struct addrinfo *saHead, *sa, hints;
	int ret, sock;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_ADDRCONFIG;

	ret = getaddrinfo(host, port, &hints, &saHead);
	if (ret) {
		fprintf(stderr, "getaddrinfo() for host '%s' failed: %s!\n", host,
			gai_strerror(ret));
		ret = -EINVAL;
		goto err_addrinfo;
	}

	for (sa = saHead; sa != NULL; sa = sa->ai_next) {
		sock = socket(sa->ai_family, sa->ai_socktype, sa->ai_protocol);
		if (sock < 0) {
			perror("socket() failed");
			continue;
		}

		if (socketFd)
			*socketFd = sock;
		else
			close(sock);

		if (addr)
			memcpy(addr, sa->ai_addr, sa->ai_addrlen);
		break;
	}

	if (!sa) {
		fprintf(stderr, "No DNS record for host %s at %s found!\n", host, port);
		ret = -EINVAL;
		goto err_dns;
	}

	ret = 0;

err_dns:
	freeaddrinfo(saHead);
err_addrinfo:
	return ret;
}

int CreateUDPSocket(const char *udpDestination, const char *udpSource, const char *udpPort,
		    int socketPriority, struct sockaddr_storage *destination)
{
	struct sockaddr_storage source;
	int ret, socketFd = -1;

	ret = DnsLookup(udpDestination, udpPort, destination, NULL);
	if (ret)
		goto err_dns1;

	ret = DnsLookup(udpSource, udpPort, &source, &socketFd);
	if (ret)
		goto err_dns2;

	switch (source.ss_family) {
	case AF_INET:
		ret = bind(socketFd, (struct sockaddr_in *)&source, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		ret = bind(socketFd, (struct sockaddr_in6 *)&source, sizeof(struct sockaddr_in6));
		break;
	default:
		ret = -EINVAL;
	}

	if (ret) {
		perror("bind() failed");
		goto err_bind;
	}

	ret = setsockopt(socketFd, SOL_SOCKET, SO_PRIORITY, &socketPriority,
			 sizeof(socketPriority));
	if (ret) {
		perror("setsockopt() failed");
		goto err_prio;
	}

	return socketFd;

err_prio:
err_bind:
	close(socketFd);
err_dns2:
err_dns1:
	return ret;
}
