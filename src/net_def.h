/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022-2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _NET_DEF_H_
#define _NET_DEF_H_

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_vlan.h>

#define ETH_P_PROFINET_RT (0x8892)
#ifndef ETH_P_LLDP
#define ETH_P_LLDP (0x88cc)
#endif
#ifndef ETH_P_OPCUA_PUBSUB
#define ETH_P_OPCUA_PUBSUB (0xb62c)
#endif
#ifndef ETH_P_AVTP
#define ETH_P_AVTP (0x22f0)
#endif

#define VLAN_ID_MASK 0x0fff
#define VLAN_PCP_SHIFT 13

/*
 * PROFINET VID values are predefined too.
 */
#define PROFINET_RT_VID_VALUE 0
#define TSN_LOW_VID_VALUE 0x102
#define TSN_HIGH_VID_VALUE 0x101

/*
 * PROFINET PCP values are predefined.
 */
#define DCP_PCP_VALUE 2
#define RTA_PCP_VALUE 3
#define RTC_PCP_VALUE 4
#define TSN_LOW_PCP_VALUE 5
#define TSN_HIGH_PCP_VALUE 6

/*
 * VLAN 802.1Q frame.
 */
struct VLANEthernetHeader
{
    unsigned char Destination[ETH_ALEN];
    unsigned char Source[ETH_ALEN];
    __be16 VLANProto;
    __be16 VLANTCI;
    __be16 VLANEncapsulatedProto;
} __attribute__((packed));

/*
 * VLAN header.
 */
struct VLANHeader
{
    __be16 VLANProto;
    __be16 VLANTCI;
} __attribute__((packed));

/*
 * MetaData for testing, error checking and coordination.
 */
struct ReferenceMetaData
{
    __be32 FrameCounter;
    __be32 CycleCounter;
} __attribute__((packed));

/*
 * PROFINET RT header.
 */
struct ProfinetRtHeader
{
    __be16 FrameId;
    struct ReferenceMetaData MetaData;
} __attribute__((packed));

struct SecurityMetaData
{
    /*
     * Bit 0:   SecurityInformation.ProtectionMode
     * Bit 1-7: Reserved
     */
    __u8 SecurityInformation;
    /*
     * Bit 0-3: NextContextID
     * Bit 4-7: CurrentContextID
     */
    __u8 SecurityControl;
    /*
     * Bit 0-31: SequenceCounter
     */
    __be32 SecuritySequenceCounter;
    /*
     * Bit 0-10:  Length
     * Bit 11-15: Reserved
     */
    __be16 SecurityLength;
} __attribute__((packed));

struct SecurityChecksum
{
    __u8 Checksum[16];
} __attribute__((packed));

/*
 * PROFINET Secure header.
 */
struct ProfinetSecureHeader
{
    __be16 FrameId;
    struct SecurityMetaData SecurityMetaData;
    struct ReferenceMetaData MetaData;
} __attribute__((packed));

/*
 * Generic Layer 2 header.
 */
struct GenericL2Header
{
    struct ReferenceMetaData MetaData;
} __attribute__((packed));

#endif /* _NET_DEF_H_ */
