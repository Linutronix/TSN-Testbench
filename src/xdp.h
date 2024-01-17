/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021-2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _XDP_H_
#define _XDP_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/if_xdp.h>

#include "app_config.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include "security.h"

#undef XSK_RING_CONS__DEFAULT_NUM_DESCS
#undef XSK_RING_PROD__DEFAULT_NUM_DESCS
#define XSK_RING_CONS__DEFAULT_NUM_DESCS 4096
#define XSK_RING_PROD__DEFAULT_NUM_DESCS 4096

#define XDP_BATCH_SIZE 512
#define XDP_NUM_FRAMES (XSK_RING_CONS__DEFAULT_NUM_DESCS + XSK_RING_PROD__DEFAULT_NUM_DESCS)
#define XDP_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE

struct XskUmemInfo
{
    struct xsk_ring_prod Fq;
    struct xsk_ring_cons Cq;
    struct xsk_umem *Umem;
    void *Buffer;
};

struct XdpSocket
{
    uint64_t OutstandingTx;
    struct xsk_ring_cons Rx;
    struct xsk_ring_prod Tx;
    struct XskUmemInfo Umem;
    struct xsk_socket *Xsk;
    struct xdp_program *Prog;
    int Fd;
    bool BusyPollMode;
};

struct XdpGenConfig
{
    enum SecurityMode Mode;
    struct SecurityContext *SecurityContext;
    const unsigned char *IvPrefix;
    const unsigned char *PayloadPattern;
    size_t PayloadPatternLength;
    size_t FrameLength;
    size_t NumFramesPerCycle;
    uint32_t *FrameNumber;
    uint64_t SequenceCounterBegin;
    uint32_t MetaDataOffset;
    void (*StatFunction)(uint64_t);
};

struct XdpSocket *XdpOpenSocket(const char *interface, const char *xdpProgram, int queue, bool skbMode,
                                bool zeroCopyMode, bool wakeupMode, bool busyPollMode);
void XdpCloseSocket(struct XdpSocket *xsk, const char *interface, bool skbMode);
void XdpCompleteTxOnly(struct XdpSocket *xsk);
void XdpCompleteTx(struct XdpSocket *xsk);
void XdpGenAndSendFrames(struct XdpSocket *xsk, const struct XdpGenConfig *xdp);
unsigned int XdpReceiveFrames(struct XdpSocket *xsk, size_t frameLength, bool mirrorEnabled,
                              int (*receiveFunction)(void *data, unsigned char *, size_t), void *data);

#endif /* _XDP_H_ */
