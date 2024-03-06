// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <linux/if_ether.h>

#include "config.h"
#include "net.h"
#include "net_def.h"
#include "security.h"
#include "utils.h"
#include "xdp.h"

void IncrementPeriod(struct timespec *time, int64_t periodNS)
{
    time->tv_nsec += periodNS;

    while (time->tv_nsec >= NSEC_PER_SEC)
    {
        /* timespec nsec overflow */
        time->tv_sec++;
        time->tv_nsec -= NSEC_PER_SEC;
    }
}

void PthreadError(int ret, const char *message)
{
    fprintf(stderr, "%s: %s\n", message, strerror(ret));
}

void SwapMacAddresses(void *buffer, size_t len)
{
    unsigned char tmp[ETH_ALEN];
    struct ethhdr *eth = buffer;

    if (len < sizeof(*eth))
        return;

    memcpy(tmp, eth->h_source, sizeof(tmp));
    memcpy(eth->h_source, eth->h_dest, sizeof(tmp));
    memcpy(eth->h_dest, tmp, sizeof(tmp));
}

void InsertVlanTag(void *buffer, size_t len, uint16_t vlanTCI)
{
    struct VLANEthernetHeader *veth;

    if (len + sizeof(struct VLANHeader) > XDP_FRAME_SIZE)
        return;

    memmove(buffer + 2 * ETH_ALEN + sizeof(struct VLANHeader), buffer + 2 * ETH_ALEN, len - 2 * ETH_ALEN);

    veth = buffer;

    veth->VLANEncapsulatedProto = htons(ETH_P_PROFINET_RT);
    veth->VLANProto = htons(ETH_P_8021Q);
    veth->VLANTCI = htons(vlanTCI);
}

void BuildVLANFrameFromRx(const unsigned char *oldFrame, size_t oldFrameLen, unsigned char *newFrame,
                          size_t newFrameLen, uint16_t etherType, uint16_t vlanTCI)
{
    struct VLANEthernetHeader *ethNew, *ethOld;

    if (newFrameLen < oldFrameLen + sizeof(struct VLANHeader))
        return;

    /* Copy payload */
    memcpy(newFrame + ETH_ALEN * 2 + sizeof(struct VLANHeader), oldFrame + ETH_ALEN * 2, oldFrameLen - ETH_ALEN * 2);

    /* Swap source destination */
    ethNew = (struct VLANEthernetHeader *)newFrame;
    ethOld = (struct VLANEthernetHeader *)oldFrame;

    memcpy(ethNew->Destination, ethOld->Source, ETH_ALEN);
    memcpy(ethNew->Source, ethOld->Destination, ETH_ALEN);

    /* Inject VLAN info */
    ethNew->VLANProto = htons(ETH_P_8021Q);
    ethNew->VLANTCI = htons(vlanTCI);
    ethNew->VLANEncapsulatedProto = htons(etherType);
}

static void InitializeSecureProfinetFrame(enum SecurityMode mode, unsigned char *frameData, size_t frameLength,
                                          const unsigned char *source, const unsigned char *destination,
                                          const char *payloadPattern, size_t payloadPatternLength, uint16_t vlanTCI,
                                          uint16_t frameId)
{
    struct ProfinetSecureHeader *rt;
    struct VLANEthernetHeader *eth;
    uint16_t securityLength;
    size_t payloadOffset;

    /* Initialize to zero */
    memset(frameData, '\0', frameLength);

    /*
     * Profinet Frame:
     *   Destination
     *   Source
     *   VLAN tag: tpid 8100, id 0x00/0x101/102, dei 0, prio 6/5/4/3/2
     *   Ether type: 8892
     *   Frame id: TSN, RTC, RTA, DCP
     *   SecurityHeader
     *   Cycle counter
     *   Payload
     *   Padding to maxFrame - Checksum
     *   SecurityChecksum
     */

    eth = (struct VLANEthernetHeader *)frameData;
    rt = (struct ProfinetSecureHeader *)(frameData + sizeof(*eth));

    /* Ethernet header */
    memcpy(eth->Destination, destination, ETH_ALEN);
    memcpy(eth->Source, source, ETH_ALEN);

    /* VLAN Header */
    eth->VLANProto = htons(ETH_P_8021Q);
    eth->VLANTCI = htons(vlanTCI);
    eth->VLANEncapsulatedProto = htons(ETH_P_PROFINET_RT);

    /* Profinet Secure header */
    securityLength = frameLength - sizeof(*eth) - sizeof(struct SecurityChecksum);
    rt->FrameId = htons(frameId);
    rt->SecurityMetaData.SecurityInformation = mode == SECURITY_MODE_AO ? 0x00 : 0x01;
    rt->SecurityMetaData.SecurityLength = htobe16(securityLength);
    rt->MetaData.FrameCounter = 0;
    rt->MetaData.CycleCounter = 0;

    /* Payload */
    payloadOffset = sizeof(*eth) + sizeof(*rt);
    memcpy(frameData + payloadOffset, payloadPattern, payloadPatternLength);

    /* SecurityChecksum is set to zero and calculated for each frame on Tx */
}

static void InitializeRtProfinetFrame(unsigned char *frameData, size_t frameLength, const unsigned char *source,
                                      const unsigned char *destination, const char *payloadPattern,
                                      size_t payloadPatternLength, uint16_t vlanTCI, uint16_t frameId)
{
    struct VLANEthernetHeader *eth;
    struct ProfinetRtHeader *rt;
    size_t payloadOffset;

    /* Initialize to zero */
    memset(frameData, '\0', frameLength);

    /*
     * Profinet Frame:
     *   Destination
     *   Source
     *   VLAN tag: tpid 8100, id 0x00/0x101/102, dei 0, prio 6/5/4/3/2
     *   Ether type: 8892
     *   Frame id: TSN, RTC, RTA, DCP
     *   Cycle counter
     *   Payload
     *   Padding to maxFrame
     */

    eth = (struct VLANEthernetHeader *)frameData;
    rt = (struct ProfinetRtHeader *)(frameData + sizeof(*eth));

    /* Ethernet header */
    memcpy(eth->Destination, destination, ETH_ALEN);
    memcpy(eth->Source, source, ETH_ALEN);

    /* VLAN Header */
    eth->VLANProto = htons(ETH_P_8021Q);
    eth->VLANTCI = htons(vlanTCI);
    eth->VLANEncapsulatedProto = htons(ETH_P_PROFINET_RT);

    /* Profinet RT header */
    rt->FrameId = htons(frameId);
    rt->MetaData.FrameCounter = 0;
    rt->MetaData.CycleCounter = 0;

    /* Payload */
    payloadOffset = sizeof(*eth) + sizeof(*rt);
    memcpy(frameData + payloadOffset, payloadPattern, payloadPatternLength);
}

void InitializeProfinetFrame(enum SecurityMode mode, unsigned char *frameData, size_t frameLength,
                             const unsigned char *source, const unsigned char *destination, const char *payloadPattern,
                             size_t payloadPatternLength, uint16_t vlanTCI, uint16_t frameId)
{
    switch (mode)
    {
    case SECURITY_MODE_NONE:
        InitializeRtProfinetFrame(frameData, frameLength, source, destination, payloadPattern, payloadPatternLength,
                                  vlanTCI, frameId);
        break;
    case SECURITY_MODE_AE:
    case SECURITY_MODE_AO:
        InitializeSecureProfinetFrame(mode, frameData, frameLength, source, destination, payloadPattern,
                                      payloadPatternLength, vlanTCI, frameId);
        break;
    }
}

int PrepareFrameForTx(const struct PrepareFrameConfig *frameConfig)
{
    /* mode == NONE may be called from PROFINET or GenericL2 */
    if (frameConfig->Mode == SECURITY_MODE_NONE)
    {
        /* Adjust meta data in frame */
        struct ReferenceMetaData *metaData =
            (struct ReferenceMetaData *)(frameConfig->FrameData + frameConfig->MetaDataOffset);

        SequenceCounterToMetaData(metaData, frameConfig->SequenceCounter, frameConfig->NumFramesPerCycle);

        return 0;
    }
    /* mode == AO is PROFINET specific */
    else if (frameConfig->Mode == SECURITY_MODE_AO)
    {
        unsigned char *beginOfSecurityChecksum;
        struct ProfinetSecureHeader *srt;
        struct VLANEthernetHeader *eth;
        unsigned char *beginOfAadData;
        struct SecurityIv iv;
        size_t sizeOfAadData;

        /* Adjust meta data first */
        srt = (struct ProfinetSecureHeader *)(frameConfig->FrameData + sizeof(*eth));
        SequenceCounterToMetaData(&srt->MetaData, frameConfig->SequenceCounter, frameConfig->NumFramesPerCycle);

        /*
         * Then, calculate checksum over data and store it at the end of the frame. The authenfication spans begins with
         * the FrameID and ends before the final security checksum.
         */
        PrepareIv(frameConfig->IvPrefix, frameConfig->SequenceCounter, &iv);
        beginOfAadData = frameConfig->FrameData + sizeof(*eth);
        sizeOfAadData = frameConfig->FrameLength - sizeof(*eth) - sizeof(struct SecurityChecksum);
        beginOfSecurityChecksum = frameConfig->FrameData + (frameConfig->FrameLength - sizeof(struct SecurityChecksum));
        return SecurityEncrypt(frameConfig->SecurityContext, NULL, 0, beginOfAadData, sizeOfAadData,
                               (unsigned char *)&iv, NULL, beginOfSecurityChecksum);
    }
    /* mode == AE is PROFINET specific too */
    else
    {
        unsigned char *beginOfSecurityChecksum;
        unsigned char *beginOfCiphertext;
        struct ProfinetSecureHeader *srt;
        struct VLANEthernetHeader *eth;
        unsigned char *beginOfAadData;
        struct SecurityIv iv;
        size_t sizeOfAadData;

        /* Adjust cycle counter first */
        srt = (struct ProfinetSecureHeader *)(frameConfig->FrameData + sizeof(*eth));
        SequenceCounterToMetaData(&srt->MetaData, frameConfig->SequenceCounter, frameConfig->NumFramesPerCycle);

        /*
         * Then, calculate checksum over data and store it at the end of the frame. The authenfication spans begins with
         * the FrameID and ends before the final security checksum. In addition, the payload pattern in encrypted and
         * stored in the frame.
         */
        PrepareIv(frameConfig->IvPrefix, frameConfig->SequenceCounter, &iv);
        beginOfAadData = frameConfig->FrameData + sizeof(*eth);
        sizeOfAadData = sizeof(*srt);
        beginOfSecurityChecksum = frameConfig->FrameData + (frameConfig->FrameLength - sizeof(struct SecurityChecksum));
        beginOfCiphertext = frameConfig->FrameData + sizeof(*eth) + sizeof(*srt);
        return SecurityEncrypt(frameConfig->SecurityContext, frameConfig->PayloadPattern,
                               frameConfig->PayloadPatternLength, beginOfAadData, sizeOfAadData, (unsigned char *)&iv,
                               beginOfCiphertext, beginOfSecurityChecksum);
    }
}

void PrepareIv(const unsigned char *ivPrefix, uint64_t sequenceCounter, struct SecurityIv *iv)
{
    /*
     * The initial vector is constructed by concatenating IvPrefix | sequenceCounter. The prefix and the counter consist
     * of six bytes each. Therefore, the sequenceCounter is converted to LE to ignore the last two upper bytes. That
     * leaves 2^48 possible counter values to create unique IVs.
     */

    memcpy(iv->IvPrefix, ivPrefix, SECURITY_IV_PREFIX_LEN);
    iv->Counter = htole64(sequenceCounter);
}

void PrepareOpenssl(struct SecurityContext *context)
{
    unsigned char iv[SECURITY_IV_LEN] = "012345678901";
    unsigned char dummyFrame[2048] = {5};

    if (!context)
        return;

    SecurityEncrypt(context, NULL, 0, dummyFrame, sizeof(dummyFrame) - sizeof(struct SecurityChecksum), iv, NULL,
                    dummyFrame + sizeof(dummyFrame) - sizeof(struct SecurityChecksum));

    SecurityDecrypt(context, NULL, 0, dummyFrame, sizeof(dummyFrame) - sizeof(struct SecurityChecksum),
                    dummyFrame + sizeof(dummyFrame) - sizeof(struct SecurityChecksum), iv, NULL);
}

int GetThreadStartTime(uint64_t baseOffset, struct timespec *wakeupTime)
{
    const uint64_t baseStartTime = appConfig.ApplicationBaseStartTimeNS;
    const clockid_t profinetClockId = appConfig.ApplicationClockId;
    int ret = 0;

    if (baseStartTime)
        NsToTs(baseStartTime + baseOffset, wakeupTime);
    else
        ret = clock_gettime(profinetClockId, wakeupTime);

    return ret;
}

static int latencyFd = -1;

void ConfigureCpuLatency(void)
{
    /* Avoid the CPU to enter deep sleep states */
    int32_t lat = 0;
    ssize_t ret;
    int fd;

    fd = open("/dev/cpu_dma_latency", O_RDWR);
    if (fd == -1)
        return;

    ret = write(fd, &lat, sizeof(lat));
    if (ret != sizeof(lat))
    {
        close(latencyFd);
        return;
    }

    latencyFd = fd;
}

void RestoreCpuLatency(void)
{
    if (latencyFd > 0)
        close(latencyFd);
}

void PrintMacAddress(const unsigned char *macAddress)
{
    int i;

    for (i = 0; i < ETH_ALEN; ++i)
    {
        printf("%02x", macAddress[i]);
        if (i != ETH_ALEN - 1)
            printf("-");
    }
}

void PrintPayloadPattern(const char *payloadPattern, size_t payloadPatternLength)
{
    size_t i;

    for (i = 0; i < payloadPatternLength; ++i)
        printf("0x%02x ", payloadPattern[i]);
}
