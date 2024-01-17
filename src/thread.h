/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _THREAD_H_
#define _THREAD_H_

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <linux/if_ether.h>

struct RingBuffer;
struct XdpSocket;
struct SecurityContext;

struct ThreadContext
{
    /* Task related */
    pthread_t RxTaskId;         /* Receiver Thread */
    uint64_t RxSequenceCounter; /* Rx cycle counter */
    pthread_t TxTaskId;         /* Sender Thread */
    pthread_t TxGenTaskId;      /* Sender generation thread */
    volatile int Stop;          /* Done? */

    /* RAW socket related */
    int SocketFd;                        /* Shared RAW socket */
    unsigned char *TxFrameData;          /* Tx frame data */
    unsigned char *RxFrameData;          /* Rx frame data */
    unsigned char Source[ETH_ALEN];      /* Source MAC Address */
    struct sockaddr_storage Destination; /* Where to send L3 frames to */
    struct RingBuffer *MirrorBuffer;     /* Rx frames to be mirrored */

    /* XDP socket related */
    struct XdpSocket *Xsk;        /* XDP socket reference */
    unsigned int ReceivedFrames;  /* Amount of frames received within cycle */
    pthread_mutex_t XdpDataMutex; /* Protect concurrent access to Xsk */

    /* Data flow related */
    struct ThreadContext *Next; /* Pointer to next traffic class */
    pthread_mutex_t DataMutex;  /* Mutex to protect frame data */
    pthread_cond_t DataCondVar; /* Cond var to signal Tx thread */
    size_t NumFramesAvailable;  /* How many frames are ready to be sent? */
    bool IsFirst;               /* Is this the first active traffic class? */

    /* Security related */
    struct SecurityContext *TxSecurityContext; /* Tx context for Auth and Crypt */
    struct SecurityContext *RxSecurityContext; /* Rx context for Auth and Crypt */

    /* Thread private data */
    void *PrivateData; /* Pointer to private data e.g, a structure */
};

enum PNThreadType
{
    TSN_HIGH_THREAD = 0,
    TSN_LOW_THREAD,
    RTC_THREAD,
    RTA_THREAD,
    DCP_THREAD,
    LLDP_THREAD,
    UDP_HIGH_THREAD,
    UDP_LOW_THREAD,
    NUM_PN_THREAD_TYPES,
};

int CreateRtThread(pthread_t *taskId, const char *threadName, int priority, int cpuCore, void *(*threadRoutine)(void *),
                   void *data);
void InitMutex(pthread_mutex_t *mutex);
void InitConditionVariable(pthread_cond_t *condVar);
int LinkPNThreads(struct ThreadContext *pnThreads);

#endif /* _THREAD_H_ */
