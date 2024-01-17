// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
/*
 * Copyright (C) 2021,2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <xdp/xdp_helpers.h>

#include "net_def.h"

struct
{
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
} xsks_map SEC(".maps");

struct
{
    __uint(priority, 10);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_sock_prog);

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *dataEnd = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct VLANEthernetHeader *veth;
    int idx = ctx->rx_queue_index;
    struct ProfinetRtHeader *rt;
    __be16 frameId;
    void *p = data;

    veth = p;
    if ((void *)(veth + 1) > dataEnd)
        return XDP_PASS;
    p += sizeof(*veth);

    /* Check for VLAN frames */
    if (veth->VLANProto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    /* Check for valid Profinet frames */
    if (veth->VLANEncapsulatedProto != bpf_htons(ETH_P_PROFINET_RT))
        return XDP_PASS;

    /* Check for VID 200 */
    if ((bpf_ntohs(veth->VLANTCI) & VLAN_ID_MASK) != 200)
        return XDP_PASS;

    /* Check frameId range */
    rt = p;
    if ((void *)(rt + 1) > dataEnd)
        return XDP_PASS;
    p += sizeof(*rt);

    frameId = bpf_htons(rt->FrameId);
    switch (frameId)
    {
    case 0x0100 ... 0x01ff: /* TSN HIGH */
    case 0x0200 ... 0x03ff: /* TSN LOW */
    case 0x8000 ... 0xbbff: /* RTC */
    case 0xfc01:            /* RTA */
        goto redirect;
    default:
        return XDP_PASS;
    }

redirect:
    /* If socket bound to rx_queue then redirect to user space */
    if (bpf_map_lookup_elem(&xsks_map, &idx))
        return bpf_redirect_map(&xsks_map, idx, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
