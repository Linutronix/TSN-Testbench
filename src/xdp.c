// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <net/if.h>
#include <netdb.h>

#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/udp.h>

#include "app_config.h"

#include "config.h"
#include "log.h"
#include "net.h"
#include "security.h"
#include "utils.h"
#include "xdp.h"

static int programLoaded;
static int xsksMap;

static enum xdp_attach_mode XdpFlags(bool skbMode)
{
    return skbMode ? XDP_MODE_SKB : XDP_MODE_NATIVE;
}

static int XdpLoadProgram(struct XdpSocket *xsk, const char *interface, const char *xdpProgram, int skbMode)
{
    struct xdp_program *prog;
    struct bpf_object *obj;
    unsigned int ifIndex;
    struct bpf_map *map;
    int ret;

    if (!xdpProgram)
    {
        fprintf(stderr, "No XDP program specified!\n");
        fprintf(stderr, "Have a look at the example configurations.\n");
        return -EINVAL;
    }

    /*
     * The eBPF program for this application instance needs to be attached
     * to the network interface only once.
     *
     * When multiple instances are executed in parallel,
     * xdp_program__attach() will try to automatically attach the new eBPF
     * program to the existing ones by utilizing the libxdp dispatcher
     * master program. Therefore, all applications have to use libxdp and
     * specify their metadata e.g., priority accordingly.
     */
    if (programLoaded)
        return 0;

    ifIndex = if_nametoindex(interface);
    if (!ifIndex)
    {
        fprintf(stderr, "if_nametoindex() failed\n");
        return -EINVAL;
    }

    prog = xdp_program__open_file(xdpProgram, "xdp_sock", NULL);
    ret = libxdp_get_error(prog);
    if (ret)
    {
        char tmp[PATH_MAX];

        /* Try to load the XDP program from data directory instead */
        snprintf(tmp, sizeof(tmp), "%s/%s", INSTALL_EBPF_DIR, xdpProgram);
        prog = xdp_program__open_file(tmp, "xdp_sock", NULL);
        ret = libxdp_get_error(prog);
        if (ret)
        {
            fprintf(stderr, "xdp_program__open_file() failed\n");
            return -EINVAL;
        }
    }

    ret = xdp_program__attach(prog, ifIndex, XdpFlags(skbMode), 0);
    if (ret)
    {
        fprintf(stderr, "xdp_program__attach() failed\n");
        return -EINVAL;
    }

    /* Locate xsks_map for AF_XDP socket code */
    obj = xdp_program__bpf_obj(prog);
    map = bpf_object__find_map_by_name(obj, "xsks_map");
    xsksMap = bpf_map__fd(map);
    if (xsksMap < 0)
    {
        fprintf(stderr, "No xsks_map found!\n");
        return -EINVAL;
    }

    programLoaded = 1;
    xsk->Prog = prog;

    return 0;
}

static int XdpConfigureSocketOptions(struct XdpSocket *xsk, bool busyPollMode)
{
    int ret = -EINVAL;

    if (!busyPollMode)
        return 0;

#if defined(HAVE_SO_BUSY_POLL) && defined(HAVE_SO_PREFER_BUSY_POLL) && defined(HAVE_SO_BUSY_POLL_BUDGET)
    int opt;

    /* busy poll enable */
    opt = 1;
    ret = setsockopt(xsk_socket__fd(xsk->Xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL, (void *)&opt, sizeof(opt));
    if (ret)
    {
        perror("setsockopt() failed");
        return ret;
    }

    /* poll for 20us if socket not ready */
    opt = 20;
    ret = setsockopt(xsk_socket__fd(xsk->Xsk), SOL_SOCKET, SO_BUSY_POLL, (void *)&opt, sizeof(opt));
    if (ret)
    {
        perror("setsockopt() failed");
        return ret;
    }

    /* send/recv XDP_BATCH_SIZE packets at most */
    opt = XDP_BATCH_SIZE;
    ret = setsockopt(xsk_socket__fd(xsk->Xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET, (void *)&opt, sizeof(opt));
    if (ret)
    {
        perror("setsockopt() failed");
        return ret;
    }

    xsk->BusyPollMode = true;
#endif

    return ret;
}

struct XdpSocket *XdpOpenSocket(const char *interface, const char *xdpProgram, int queue, bool skbMode,
                                bool zeroCopyMode, bool wakeupMode, bool busyPollMode)
{
    struct xsk_umem_config cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = XDP_FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };
    struct xsk_socket_config xskCfg;
    struct XdpSocket *xsk;
    void *buffer = NULL;
    int ret, i, fd;
    uint32_t idx;

    xsk = malloc(sizeof(*xsk));
    if (!xsk)
        return NULL;
    memset(xsk, '\0', sizeof(*xsk));

    ret = XdpLoadProgram(xsk, interface, xdpProgram, skbMode);
    if (ret)
        goto err;

    /* Allocate user space memory for xdp frames */
    ret = posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE), XDP_NUM_FRAMES * XDP_FRAME_SIZE);
    if (ret)
    {
        fprintf(stderr, "posix_memalign() failed\n");
        goto err;
    }
    memset(buffer, '\0', XDP_NUM_FRAMES * XDP_FRAME_SIZE);

    ret =
        xsk_umem__create(&xsk->Umem.Umem, buffer, XDP_NUM_FRAMES * XDP_FRAME_SIZE, &xsk->Umem.Fq, &xsk->Umem.Cq, &cfg);
    if (ret)
    {
        fprintf(stderr, "xsk_umem__create() failed: %s\n", strerror(-ret));
        goto err2;
    }
    xsk->Umem.Buffer = buffer;

    /* Add some buffers */
    ret = xsk_ring_prod__reserve(&xsk->Umem.Fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
    {
        fprintf(stderr, "xsk_ring_prod__reserve() failed\n");
        goto err3;
    }

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&xsk->Umem.Fq, idx++) = i * XDP_FRAME_SIZE;

    xsk_ring_prod__submit(&xsk->Umem.Fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    /* Create XDP socket */
    xskCfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xskCfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xskCfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    xskCfg.xdp_flags = skbMode ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
    xskCfg.bind_flags = wakeupMode ? XDP_USE_NEED_WAKEUP : 0;
    xskCfg.bind_flags |= zeroCopyMode ? XDP_ZEROCOPY : XDP_COPY;

    ret = xsk_socket__create(&xsk->Xsk, interface, queue, xsk->Umem.Umem, &xsk->Rx, &xsk->Tx, &xskCfg);
    if (ret)
    {
        fprintf(stderr, "xsk_socket__create() failed: %s\n", strerror(-ret));
        goto err3;
    }

    /* Add xsk into xsks_map */
    fd = xsk_socket__fd(xsk->Xsk);
    ret = bpf_map_update_elem(xsksMap, &queue, &fd, 0);
    if (ret)
    {
        fprintf(stderr, "bpf_map_update_elem() failed: %s\n", strerror(-ret));
        goto err4;
    }

    /* Set socket options */
    ret = XdpConfigureSocketOptions(xsk, busyPollMode);
    if (ret)
    {
        fprintf(stderr, "Failed to configure busy polling!\n");
        goto err4;
    }

    return xsk;

err4:
    xsk_socket__delete(xsk->Xsk);
err3:
    xsk_umem__delete(xsk->Umem.Umem);
err2:
    free(buffer);
err:
    free(xsk);
    return NULL;
}

void XdpCloseSocket(struct XdpSocket *xsk, const char *interface, bool skbMode)
{
    unsigned int ifIndex;

    if (!xsk)
        return;

    xsk_socket__delete(xsk->Xsk);
    xsk_umem__delete(xsk->Umem.Umem);

    ifIndex = if_nametoindex(interface);
    if (!ifIndex)
    {
        fprintf(stderr, "if_nametoindex() failed\n");
        return;
    }

    if (xsk->Prog)
    {
        xdp_program__detach(xsk->Prog, ifIndex, XdpFlags(skbMode), 0);
        xdp_program__close(xsk->Prog);
        programLoaded = 0;
    }

    free(xsk->Umem.Buffer);
    free(xsk);
}

void XdpCompleteTxOnly(struct XdpSocket *xsk)
{
    size_t ndescs = xsk->OutstandingTx;
    unsigned int received;
    uint32_t idxCq = 0;

    if (!xsk->OutstandingTx)
        return;

    /* Kick kernel to Tx packets */
    if (xsk->BusyPollMode || xsk_ring_prod__needs_wakeup(&xsk->Tx))
        sendto(xsk_socket__fd(xsk->Xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    /* Buffers transmitted? */
    received = xsk_ring_cons__peek(&xsk->Umem.Cq, ndescs, &idxCq);
    if (!received)
        return;

    xsk_ring_cons__release(&xsk->Umem.Cq, received);
    xsk->OutstandingTx -= received;
}

void XdpCompleteTx(struct XdpSocket *xsk)
{
    size_t ndescs = xsk->OutstandingTx;
    uint32_t idxCq = 0, idxFq = 0;
    unsigned int received;
    int ret, i;

    if (!xsk->OutstandingTx)
        return;

    /* Kick kernel to Tx packets */
    if (xsk->BusyPollMode || xsk_ring_prod__needs_wakeup(&xsk->Tx))
        sendto(xsk_socket__fd(xsk->Xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    /* Buffers transmitted? */
    received = xsk_ring_cons__peek(&xsk->Umem.Cq, ndescs, &idxCq);
    if (!received)
        return;

    /* Re-add for Rx */
    ret = xsk_ring_prod__reserve(&xsk->Umem.Fq, received, &idxFq);
    while (ret != received)
    {
        if (ret < 0)
            LogMessage(LOG_LEVEL_ERROR, "xsk_ring_prod__reserve() failed\n");

        if (xsk->BusyPollMode || xsk_ring_prod__needs_wakeup(&xsk->Umem.Fq))
            recvfrom(xsk_socket__fd(xsk->Xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        ret = xsk_ring_prod__reserve(&xsk->Umem.Fq, received, &idxFq);
    }

    for (i = 0; i < received; ++i)
        *xsk_ring_prod__fill_addr(&xsk->Umem.Fq, idxFq++) = *xsk_ring_cons__comp_addr(&xsk->Umem.Cq, idxCq++);

    xsk_ring_prod__submit(&xsk->Umem.Fq, received);
    xsk_ring_cons__release(&xsk->Umem.Cq, received);
    xsk->OutstandingTx -= received;
}

void XdpGenAndSendFrames(struct XdpSocket *xsk, const struct XdpGenConfig *xdp)
{
    uint32_t idx;
    size_t i;

    if (xdp->NumFramesPerCycle == 0)
        return;

    if (xsk_ring_prod__reserve(&xsk->Tx, xdp->NumFramesPerCycle, &idx) < xdp->NumFramesPerCycle)
    {
        /*
         * This should never happen. It means there're no more Tx
         * descriptors available to transmit the frames from this very
         * period. The only thing we can do here, is to come back later
         * and hope the hardware did transmit some frames.
         */
        LogMessage(LOG_LEVEL_ERROR, "XdpTx: Cannot allocate Tx descriptors!\n");
        XdpCompleteTxOnly(xsk);
        return;
    }

    for (i = 0; i < xdp->NumFramesPerCycle; ++i)
    {
        struct xdp_desc *txDesc = xsk_ring_prod__tx_desc(&xsk->Tx, idx + i);
        struct PrepareFrameConfig frameConfig;
        struct VLANEthernetHeader *eth;
        unsigned char *data;
        int ret;

        txDesc->addr = *xdp->FrameNumber * XDP_FRAME_SIZE;
        txDesc->len = xdp->FrameLength;

        *xdp->FrameNumber += 1;
        *xdp->FrameNumber = (*xdp->FrameNumber % XSK_RING_CONS__DEFAULT_NUM_DESCS) + XSK_RING_PROD__DEFAULT_NUM_DESCS;

        /* Get frame and prepare it */
        data = xsk_umem__get_data(xsk->Umem.Buffer, txDesc->addr);

        frameConfig.Mode = xdp->Mode;
        frameConfig.SecurityContext = xdp->SecurityContext;
        frameConfig.IvPrefix = xdp->IvPrefix;
        frameConfig.PayloadPattern = xdp->PayloadPattern;
        frameConfig.PayloadPatternLength = xdp->PayloadPatternLength;
        frameConfig.FrameData = data;
        frameConfig.FrameLength = xdp->FrameLength;
        frameConfig.NumFramesPerCycle = xdp->NumFramesPerCycle;
        frameConfig.SequenceCounter = xdp->SequenceCounterBegin + i;
        frameConfig.MetaDataOffset = xdp->MetaDataOffset;

        ret = PrepareFrameForTx(&frameConfig);

        if (ret)
            LogMessage(LOG_LEVEL_ERROR, "XdpTx: Failed to prepare frame for Tx!\n");

        /*
         * In debug monitor mode the first frame of each burst should
         * have a different DA. This way, the oscilloscope can trigger
         * for it.
         */
        if (appConfig.DebugMonitorMode && i == 0)
        {
            eth = (struct VLANEthernetHeader *)data;
            memcpy(eth->Destination, appConfig.DebugMonitorDestination, ETH_ALEN);
        }
    }

    xsk_ring_prod__submit(&xsk->Tx, xdp->NumFramesPerCycle);
    xsk->OutstandingTx += xdp->NumFramesPerCycle;

    /* Kick Tx */
    XdpCompleteTxOnly(xsk);

    /* Log */
    for (i = 0; i < xdp->NumFramesPerCycle; ++i)
        StatFrameSent(xdp->FrameType, xdp->SequenceCounterBegin + i);
}

unsigned int XdpReceiveFrames(struct XdpSocket *xsk, size_t frameLength, bool mirrorEnabled,
                              int (*receiveFunction)(void *data, unsigned char *, size_t), void *data)
{
    uint32_t idxRx = 0, idxTx = 0, idxFq = 0, len;
    unsigned int received, i;
    unsigned char *packet;
    uint64_t addr, orig;
    int ret;

    /* Receive frames when in busy polling mode */
    if (xsk->BusyPollMode)
        recvfrom(xsk_socket__fd(xsk->Xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);

    /* Check for received frames */
    received = xsk_ring_cons__peek(&xsk->Rx, XDP_BATCH_SIZE, &idxRx);
    if (!received)
    {
        if (xsk_ring_prod__needs_wakeup(&xsk->Umem.Fq))
            recvfrom(xsk_socket__fd(xsk->Xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        return 0;
    }

    /*
     * For mirror reserve space in Tx queue to re-transmit the
     * frames. Otherwise, recycle the Rx frames immediately.
     */
    if (mirrorEnabled)
    {
        /* Reserve space in Tx ring */
        ret = xsk_ring_prod__reserve(&xsk->Tx, received, &idxTx);
        while (ret != received)
        {
            if (ret < 0)
                LogMessage(LOG_LEVEL_ERROR, "xsk_ring_prod__reserve() failed\n");

            if (xsk->BusyPollMode || xsk_ring_prod__needs_wakeup(&xsk->Tx))
                recvfrom(xsk_socket__fd(xsk->Xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
            ret = xsk_ring_prod__reserve(&xsk->Tx, received, &idxTx);
        }
    }
    else
    {
        /* Reserve space in fill queue */
        ret = xsk_ring_prod__reserve(&xsk->Umem.Fq, received, &idxFq);
        while (ret != received)
        {
            if (ret < 0)
                LogMessage(LOG_LEVEL_ERROR, "xsk_ring_prod__reserve() failed\n");

            if (xsk->BusyPollMode || xsk_ring_prod__needs_wakeup(&xsk->Umem.Fq))
                recvfrom(xsk_socket__fd(xsk->Xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
            ret = xsk_ring_prod__reserve(&xsk->Umem.Fq, received, &idxFq);
        }
    }

    for (i = 0; i < received; ++i)
    {
        /* Get the packet */
        addr = xsk_ring_cons__rx_desc(&xsk->Rx, idxRx)->addr;
        len = xsk_ring_cons__rx_desc(&xsk->Rx, idxRx++)->len;
        orig = xsk_umem__extract_addr(addr);

        /* Parse it */
        addr = xsk_umem__add_offset_to_addr(addr);
        packet = xsk_umem__get_data(xsk->Umem.Buffer, addr);

        if (mirrorEnabled)
        {
            /* Store received frame in Tx ring */
            xsk_ring_prod__tx_desc(&xsk->Tx, idxTx)->addr = orig;
            xsk_ring_prod__tx_desc(&xsk->Tx, idxTx++)->len = frameLength;
        }
        else
        {
            /* Move buffer back to fill queue */
            *xsk_ring_prod__fill_addr(&xsk->Umem.Fq, idxFq++) = orig;
        }

        receiveFunction(data, packet, len);
    }

    if (mirrorEnabled)
    {
        xsk_ring_cons__release(&xsk->Rx, received);
    }
    else
    {
        xsk_ring_prod__submit(&xsk->Umem.Fq, received);
        xsk_ring_cons__release(&xsk->Rx, received);
    }

    return received;
}
