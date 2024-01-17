// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2022 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/mman.h>

#include "app_config.h"
#include "config.h"
#include "dcp_thread.h"
#include "layer2_thread.h"
#include "lldp_thread.h"
#include "log.h"
#include "rta_thread.h"
#include "rtc_thread.h"
#include "stat.h"
#include "thread.h"
#include "tsn_thread.h"
#include "udp_thread.h"
#include "utils.h"

static struct option longOptions[] = {
    {"config", optional_argument, NULL, 'c'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'V'},
    {NULL},
};

static void PrintUsageAndDie(void)
{
    fprintf(stderr, "usage: mirror [options]\n");
    fprintf(stderr, "  options:\n");
    fprintf(stderr, "    -h, --help:    Print this help text\n");
    fprintf(stderr, "    -V, --version: Print version\n");
    fprintf(stderr, "    -c, --config:  Path to config file\n");

    exit(EXIT_SUCCESS);
}

static void PrintVersionAndDie(void)
{
    printf("mirror: version \"%s\"\n", VERSION);
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    struct LogThreadContext *logThread;
    struct ThreadContext *g2Threads;
    struct ThreadContext *threads;
    const char *configFile = NULL;
    int c, ret;

    while ((c = getopt_long(argc, argv, "c:hV", longOptions, NULL)) != -1)
    {
        switch (c)
        {
        case 'V':
            PrintVersionAndDie();
            break;
        case 'c':
            configFile = optarg;
            break;
        case 'h':
        default:
            PrintUsageAndDie();
        }
    }

    /*
     * The "mirror" application only mirrors traffic and never generate
     * frames itself. Make sure, the corresponding options are set.
     *
     * Note: The user cannot override this.
     */
    ret = ConfigSetDefaults(true);
    if (ret)
    {
        fprintf(stderr, "Failed to set default config values!\n");
        exit(EXIT_FAILURE);
    }
    if (configFile)
    {
        ret = ConfigReadFromFile(configFile);
        if (ret)
        {
            fprintf(stderr, "Failed to parse configuration file!\n");
            exit(EXIT_FAILURE);
        }
    }

    ConfigPrintValues();

    if (!ConfigSanityCheck())
    {
        fprintf(stderr, "Configuration failed sanity checks!\n");
        exit(EXIT_FAILURE);
    }

    if (mlockall(MCL_CURRENT | MCL_FUTURE))
    {
        perror("mlockall() failed");
        exit(EXIT_FAILURE);
    }

    ConfigureCpuLatency();

    ret = LogInit();
    if (ret)
    {
        fprintf(stderr, "Failed to initialize logging!\n");
        exit(EXIT_FAILURE);
    }

    ret = StatInit(false);
    if (ret)
    {
        fprintf(stderr, "Failed to initialize statistics!\n");
        exit(EXIT_FAILURE);
    }

    logThread = LogThreadCreate();
    if (!logThread)
    {
        fprintf(stderr, "Failed to create and start Log Thread!\n");
        exit(EXIT_FAILURE);
    }

    g2Threads = GenericL2ThreadsCreate();
    if (!g2Threads)
    {
        fprintf(stderr, "Failed to create and start Generic L2 Threads!\n");
        exit(EXIT_FAILURE);
    }

    threads = calloc(NUM_PN_THREAD_TYPES, sizeof(struct ThreadContext));
    if (!threads)
    {
        fprintf(stderr, "Failed to allocate PN threads!\n");
        exit(EXIT_FAILURE);
    }

    if (LinkPNThreads(threads))
    {
        fprintf(stderr, "Failed to determine PN traffic classes order!\n");
        exit(EXIT_FAILURE);
    }

    ret = UdpLowThreadsCreate(&threads[UDP_LOW_THREAD]);
    if (ret)
    {
        fprintf(stderr, "Failed to create and start UDP Low Threads!\n");
        exit(EXIT_FAILURE);
    }

    ret = UdpHighThreadsCreate(&threads[UDP_HIGH_THREAD]);
    if (ret)
    {
        fprintf(stderr, "Failed to create and start UDP High Threads!\n");
        exit(EXIT_FAILURE);
    }

    ret = LldpThreadsCreate(&threads[LLDP_THREAD]);
    if (ret)
    {
        fprintf(stderr, "Failed to create and start LLDP Threads!\n");
        exit(EXIT_FAILURE);
    }

    ret = DcpThreadsCreate(&threads[DCP_THREAD]);
    if (ret)
    {
        fprintf(stderr, "Failed to create and start DCP Threads!\n");
        exit(EXIT_FAILURE);
    }

    ret = RtaThreadsCreate(&threads[RTA_THREAD]);
    if (ret)
    {
        fprintf(stderr, "Failed to create and start RTA Threads!\n");
        exit(EXIT_FAILURE);
    }

    ret = RtcThreadsCreate(&threads[RTC_THREAD]);
    if (ret)
    {
        fprintf(stderr, "Failed to create and start RTC Threads!\n");
        exit(EXIT_FAILURE);
    }

    ret = TsnLowThreadsCreate(&threads[TSN_LOW_THREAD]);
    if (ret)
    {
        fprintf(stderr, "Failed to create and start TSN Low Threads!\n");
        exit(EXIT_FAILURE);
    }

    ret = TsnHighThreadsCreate(&threads[TSN_HIGH_THREAD]);
    if (ret)
    {
        fprintf(stderr, "Failed to create and start TSN High Threads!\n");
        exit(EXIT_FAILURE);
    }

    TsnHighThreadsWaitForFinish(&threads[TSN_HIGH_THREAD]);
    TsnLowThreadsWaitForFinish(&threads[TSN_LOW_THREAD]);
    RtcThreadsWaitForFinish(&threads[RTC_THREAD]);
    RtaThreadsWaitForFinish(&threads[RTA_THREAD]);
    DcpThreadsWaitForFinish(&threads[DCP_THREAD]);
    LldpThreadsWaitForFinish(&threads[LLDP_THREAD]);
    UdpHighThreadsWaitForFinish(&threads[UDP_HIGH_THREAD]);
    UdpLowThreadsWaitForFinish(&threads[UDP_LOW_THREAD]);
    GenericL2ThreadsWaitForFinish(g2Threads);
    LogThreadWaitForFinish(logThread);

    StatFree();
    LogFree();
    ConfigFree();
    free(threads);

    RestoreCpuLatency();

    return EXIT_SUCCESS;
}
