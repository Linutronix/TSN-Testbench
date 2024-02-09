/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "app_config.h"

#include "security.h"

struct ApplicationConfig
{
    /* Application scheduling configuration */
    clockid_t ApplicationClockId;
    uint64_t ApplicationBaseCycleTimeNS;
    uint64_t ApplicationBaseStartTimeNS;
    uint64_t ApplicationTxBaseOffsetNS;
    uint64_t ApplicationRxBaseOffsetNS;
    char *ApplicationXdpProgram;
    size_t ApplicationXdpProgramLength;
    /* TSN High */
    bool TsnHighTxEnabled;
    bool TsnHighRxEnabled;
    bool TsnHighRxMirrorEnabled;
    bool TsnHighXdpEnabled;
    bool TsnHighXdpSkbMode;
    bool TsnHighXdpZcMode;
    bool TsnHighXdpWakeupMode;
    bool TsnHighXdpBusyPollMode;
    bool TsnHighTxTimeEnabled;
    bool TsnHighIgnoreRxErrors;
    uint64_t TsnHighTxTimeOffsetNS;
    int TsnHighVid;
    size_t TsnHighNumFramesPerCycle;
    char *TsnHighPayloadPattern;
    size_t TsnHighPayloadPatternLength;
    size_t TsnHighFrameLength;
    enum SecurityMode TsnHighSecurityMode;
    enum SecurityAlgorithm TsnHighSecurityAlgorithm;
    char *TsnHighSecurityKey;
    size_t TsnHighSecurityKeyLength;
    char *TsnHighSecurityIvPrefix;
    size_t TsnHighSecurityIvPrefixLength;
    int TsnHighRxQueue;
    int TsnHighTxQueue;
    int TsnHighSocketPriority;
    int TsnHighTxThreadPriority;
    int TsnHighRxThreadPriority;
    int TsnHighTxThreadCpu;
    int TsnHighRxThreadCpu;
    char TsnHighInterface[IF_NAMESIZE];
    unsigned char TsnHighDestination[ETH_ALEN];
    /* TSN Low */
    bool TsnLowTxEnabled;
    bool TsnLowRxEnabled;
    bool TsnLowRxMirrorEnabled;
    bool TsnLowXdpEnabled;
    bool TsnLowXdpSkbMode;
    bool TsnLowXdpZcMode;
    bool TsnLowXdpWakeupMode;
    bool TsnLowXdpBusyPollMode;
    bool TsnLowTxTimeEnabled;
    bool TsnLowIgnoreRxErrors;
    uint64_t TsnLowTxTimeOffsetNS;
    int TsnLowVid;
    size_t TsnLowNumFramesPerCycle;
    char *TsnLowPayloadPattern;
    size_t TsnLowPayloadPatternLength;
    size_t TsnLowFrameLength;
    enum SecurityMode TsnLowSecurityMode;
    enum SecurityAlgorithm TsnLowSecurityAlgorithm;
    char *TsnLowSecurityKey;
    size_t TsnLowSecurityKeyLength;
    char *TsnLowSecurityIvPrefix;
    size_t TsnLowSecurityIvPrefixLength;
    int TsnLowRxQueue;
    int TsnLowTxQueue;
    int TsnLowSocketPriority;
    int TsnLowTxThreadPriority;
    int TsnLowRxThreadPriority;
    int TsnLowTxThreadCpu;
    int TsnLowRxThreadCpu;
    char TsnLowInterface[IF_NAMESIZE];
    unsigned char TsnLowDestination[ETH_ALEN];
    /* Real Time Cyclic (RTC) */
    bool RtcTxEnabled;
    bool RtcRxEnabled;
    bool RtcRxMirrorEnabled;
    bool RtcXdpEnabled;
    bool RtcXdpSkbMode;
    bool RtcXdpZcMode;
    bool RtcXdpWakeupMode;
    bool RtcXdpBusyPollMode;
    bool RtcIgnoreRxErrors;
    int RtcVid;
    size_t RtcNumFramesPerCycle;
    char *RtcPayloadPattern;
    size_t RtcPayloadPatternLength;
    size_t RtcFrameLength;
    enum SecurityMode RtcSecurityMode;
    enum SecurityAlgorithm RtcSecurityAlgorithm;
    char *RtcSecurityKey;
    size_t RtcSecurityKeyLength;
    char *RtcSecurityIvPrefix;
    size_t RtcSecurityIvPrefixLength;
    int RtcRxQueue;
    int RtcTxQueue;
    int RtcSocketPriority;
    int RtcTxThreadPriority;
    int RtcRxThreadPriority;
    int RtcTxThreadCpu;
    int RtcRxThreadCpu;
    char RtcInterface[IF_NAMESIZE];
    unsigned char RtcDestination[ETH_ALEN];
    /* Real Time Acyclic (RTA) */
    bool RtaTxEnabled;
    bool RtaRxEnabled;
    bool RtaTxGenEnabled;
    bool RtaRxMirrorEnabled;
    bool RtaXdpEnabled;
    bool RtaXdpSkbMode;
    bool RtaXdpZcMode;
    bool RtaXdpWakeupMode;
    bool RtaXdpBusyPollMode;
    bool RtaIgnoreRxErrors;
    int RtaVid;
    uint64_t RtaBurstPeriodNS;
    size_t RtaNumFramesPerCycle;
    char *RtaPayloadPattern;
    size_t RtaPayloadPatternLength;
    size_t RtaFrameLength;
    enum SecurityMode RtaSecurityMode;
    enum SecurityAlgorithm RtaSecurityAlgorithm;
    char *RtaSecurityKey;
    size_t RtaSecurityKeyLength;
    char *RtaSecurityIvPrefix;
    size_t RtaSecurityIvPrefixLength;
    int RtaRxQueue;
    int RtaTxQueue;
    int RtaSocketPriority;
    int RtaTxThreadPriority;
    int RtaRxThreadPriority;
    int RtaTxThreadCpu;
    int RtaRxThreadCpu;
    char RtaInterface[IF_NAMESIZE];
    unsigned char RtaDestination[ETH_ALEN];
    /* Discovery and Configuration Protocol (DCP) */
    bool DcpTxEnabled;
    bool DcpRxEnabled;
    bool DcpTxGenEnabled;
    bool DcpRxMirrorEnabled;
    bool DcpIgnoreRxErrors;
    int DcpVid;
    uint64_t DcpBurstPeriodNS;
    size_t DcpNumFramesPerCycle;
    char *DcpPayloadPattern;
    size_t DcpPayloadPatternLength;
    size_t DcpFrameLength;
    int DcpRxQueue;
    int DcpTxQueue;
    int DcpSocketPriority;
    int DcpTxThreadPriority;
    int DcpRxThreadPriority;
    int DcpTxThreadCpu;
    int DcpRxThreadCpu;
    char DcpInterface[IF_NAMESIZE];
    unsigned char DcpDestination[ETH_ALEN];
    /* Link Layer Discovery Protocol (LLDP) */
    bool LldpTxEnabled;
    bool LldpRxEnabled;
    bool LldpTxGenEnabled;
    bool LldpRxMirrorEnabled;
    bool LldpIgnoreRxErrors;
    uint64_t LldpBurstPeriodNS;
    size_t LldpNumFramesPerCycle;
    char *LldpPayloadPattern;
    size_t LldpPayloadPatternLength;
    size_t LldpFrameLength;
    int LldpRxQueue;
    int LldpTxQueue;
    int LldpSocketPriority;
    int LldpTxThreadPriority;
    int LldpRxThreadPriority;
    int LldpTxThreadCpu;
    int LldpRxThreadCpu;
    char LldpInterface[IF_NAMESIZE];
    unsigned char LldpDestination[ETH_ALEN];
    /* User Datagram Protocol (UDP) High */
    bool UdpHighTxEnabled;
    bool UdpHighRxEnabled;
    bool UdpHighTxGenEnabled;
    bool UdpHighRxMirrorEnabled;
    bool UdpHighIgnoreRxErrors;
    uint64_t UdpHighBurstPeriodNS;
    size_t UdpHighNumFramesPerCycle;
    char *UdpHighPayloadPattern;
    size_t UdpHighPayloadPatternLength;
    size_t UdpHighFrameLength;
    int UdpHighRxQueue;
    int UdpHighTxQueue;
    int UdpHighSocketPriority;
    int UdpHighTxThreadPriority;
    int UdpHighRxThreadPriority;
    int UdpHighTxThreadCpu;
    int UdpHighRxThreadCpu;
    char UdpHighInterface[IF_NAMESIZE];
    char *UdpHighPort;
    size_t UdpHighPortLength;
    char *UdpHighDestination;
    size_t UdpHighDestinationLength;
    char *UdpHighSource;
    size_t UdpHighSourceLength;
    /* User Datagram Protocol (UDP) Low */
    bool UdpLowTxEnabled;
    bool UdpLowRxEnabled;
    bool UdpLowTxGenEnabled;
    bool UdpLowRxMirrorEnabled;
    bool UdpLowIgnoreRxErrors;
    uint64_t UdpLowBurstPeriodNS;
    size_t UdpLowNumFramesPerCycle;
    char *UdpLowPayloadPattern;
    size_t UdpLowPayloadPatternLength;
    size_t UdpLowFrameLength;
    int UdpLowRxQueue;
    int UdpLowTxQueue;
    int UdpLowSocketPriority;
    int UdpLowTxThreadPriority;
    int UdpLowRxThreadPriority;
    int UdpLowTxThreadCpu;
    int UdpLowRxThreadCpu;
    char UdpLowInterface[IF_NAMESIZE];
    char *UdpLowPort;
    size_t UdpLowPortLength;
    char *UdpLowDestination;
    size_t UdpLowDestinationLength;
    char *UdpLowSource;
    size_t UdpLowSourceLength;
    /* Generic Layer 2 (example: OPC/UA PubSub) */
    char *GenericL2Name;
    size_t GenericL2NameLength;
    bool GenericL2TxEnabled;
    bool GenericL2RxEnabled;
    bool GenericL2RxMirrorEnabled;
    bool GenericL2XdpEnabled;
    bool GenericL2XdpSkbMode;
    bool GenericL2XdpZcMode;
    bool GenericL2XdpWakeupMode;
    bool GenericL2XdpBusyPollMode;
    bool GenericL2TxTimeEnabled;
    bool GenericL2IgnoreRxErrors;
    uint64_t GenericL2TxTimeOffsetNS;
    int GenericL2Vid;
    int GenericL2Pcp;
    unsigned int GenericL2EtherType;
    size_t GenericL2NumFramesPerCycle;
    char *GenericL2PayloadPattern;
    size_t GenericL2PayloadPatternLength;
    size_t GenericL2FrameLength;
    int GenericL2RxQueue;
    int GenericL2TxQueue;
    int GenericL2SocketPriority;
    int GenericL2TxThreadPriority;
    int GenericL2RxThreadPriority;
    int GenericL2TxThreadCpu;
    int GenericL2RxThreadCpu;
    char GenericL2Interface[IF_NAMESIZE];
    unsigned char GenericL2Destination[ETH_ALEN];
    /* Logging */
    uint64_t LogThreadPeriodNS;
    int LogThreadPriority;
    int LogThreadCpu;
    char *LogFile;
    size_t LogFileLength;
    char *LogLevel;
    size_t LogLevelLength;
    /* Debug */
    bool DebugStopTraceOnRtt;
    bool DebugStopTraceOnError;
    uint64_t DebugStopTraceRttLimitNS;
    bool DebugMonitorMode;
    unsigned char DebugMonitorDestination[ETH_ALEN];
    /* Statistics */
    uint64_t StatsCollectionIntervalNS;
    /* Log through MQTT */
    bool LogViaMQTT;
    int LogViaMQTTThreadPriority;
    int LogViaMQTTThreadCpu;
    uint64_t LogViaMQTTThreadPeriodNS;
    size_t LogViaMQTTBrokerIPLength;
    char *LogViaMQTTBrokerIP;
    int LogViaMQTTBrokerPort;
    int LogViaMQTTKeepAliveSecs;
    size_t LogViaMQTTMeasurementNameLength;
    char *LogViaMQTTMeasurementName;
};

extern struct ApplicationConfig appConfig;

int ConfigReadFromFile(const char *configFile);
int ConfigSetDefaults(bool mirrorEnabled);
void ConfigPrintValues(void);
bool ConfigSanityCheck(void);
void ConfigFree(void);

#define CONFIG_STORE_BOOL_PARAM(name)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!strcmp(key, #name))                                                                                       \
        {                                                                                                              \
            if (!strcmp(value, "0") || !strcasecmp(value, "false"))                                                    \
                appConfig.name = false;                                                                                \
            else if (!strcmp(value, "1") || !strcasecmp(value, "true"))                                                \
                appConfig.name = true;                                                                                 \
            else                                                                                                       \
            {                                                                                                          \
                fprintf(stderr, "The value for " #name " is invalid!\n");                                              \
                goto err_parse;                                                                                        \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

#define CONFIG_STORE_INT_PARAM(name)                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!strcmp(key, #name))                                                                                       \
        {                                                                                                              \
            appConfig.name = strtol(value, &endptr, 10);                                                               \
            if (errno != 0 || endptr == value || *endptr != '\0')                                                      \
            {                                                                                                          \
                ret = -ERANGE;                                                                                         \
                fprintf(stderr, "The value for " #name " is invalid!\n");                                              \
                goto err_parse;                                                                                        \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

#define CONFIG_STORE_ULONG_PARAM(name)                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!strcmp(key, #name))                                                                                       \
        {                                                                                                              \
            appConfig.name = strtoull(value, &endptr, 10);                                                             \
            if (errno != 0 || endptr == value || *endptr != '\0')                                                      \
            {                                                                                                          \
                ret = -ERANGE;                                                                                         \
                fprintf(stderr, "The value for " #name " is invalid!\n");                                              \
                goto err_parse;                                                                                        \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

#define CONFIG_STORE_STRING_PARAM(name)                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!strcmp(key, #name))                                                                                       \
        {                                                                                                              \
            appConfig.name = strdup(value);                                                                            \
            if (!appConfig.name)                                                                                       \
            {                                                                                                          \
                ret = -ENOMEM;                                                                                         \
                fprintf(stderr, "strdup() for " #name " failed!\n");                                                   \
                goto err_parse;                                                                                        \
            }                                                                                                          \
            appConfig.name##Length = strlen(value);                                                                    \
        }                                                                                                              \
    } while (0)

#define CONFIG_STORE_INTERFACE_PARAM(name)                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!strcmp(key, #name))                                                                                       \
            strncpy(appConfig.name, value, sizeof(appConfig.name) - 1);                                                \
    } while (0)

#define CONFIG_STORE_MAC_PARAM(name)                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!strcmp(key, #name))                                                                                       \
        {                                                                                                              \
            unsigned int tmp[ETH_ALEN];                                                                                \
            int i;                                                                                                     \
                                                                                                                       \
            ret = sscanf(value, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);            \
                                                                                                                       \
            if (ret != ETH_ALEN)                                                                                       \
            {                                                                                                          \
                fprintf(stderr, "Failed to parse MAC Address!\n");                                                     \
                ret = -EINVAL;                                                                                         \
                goto err_parse;                                                                                        \
            }                                                                                                          \
                                                                                                                       \
            for (i = 0; i < ETH_ALEN; ++i)                                                                             \
                appConfig.name[i] = (unsigned char)tmp[i];                                                             \
        }                                                                                                              \
    } while (0)

#define CONFIG_STORE_CLOCKID_PARAM(name)                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!strcmp(key, #name))                                                                                       \
        {                                                                                                              \
            if (strcmp(value, "CLOCK_TAI") && strcmp(value, "CLOCK_MONOTONIC"))                                        \
            {                                                                                                          \
                fprintf(stderr, "Invalid clockid specified!\n");                                                       \
                goto err_parse;                                                                                        \
            }                                                                                                          \
                                                                                                                       \
            if (!strcmp(value, "CLOCK_TAI"))                                                                           \
                appConfig.name = CLOCK_TAI;                                                                            \
            if (!strcmp(value, "CLOCK_MONOTONIC"))                                                                     \
                appConfig.name = CLOCK_MONOTONIC;                                                                      \
        }                                                                                                              \
    } while (0)

#define CONFIG_STORE_ETHER_TYPE(name)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!strcmp(key, #name))                                                                                       \
        {                                                                                                              \
            appConfig.name = strtoul(value, &endptr, 16);                                                              \
            if (errno != 0 || endptr == value || *endptr != '\0')                                                      \
            {                                                                                                          \
                ret = -ERANGE;                                                                                         \
                fprintf(stderr, "The value for " #name " is invalid!\n");                                              \
                goto err_parse;                                                                                        \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

#define CONFIG_STORE_SECURITY_MODE_PARAM(name)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!strcmp(key, #name))                                                                                       \
        {                                                                                                              \
            if (strcasecmp(value, "none") && strcasecmp(value, "ao") && strcasecmp(value, "ae"))                       \
            {                                                                                                          \
                fprintf(stderr, "Invalid security mode specified!\n");                                                 \
                goto err_parse;                                                                                        \
            }                                                                                                          \
                                                                                                                       \
            if (!strcasecmp(value, "none"))                                                                            \
                appConfig.name = SECURITY_MODE_NONE;                                                                   \
            if (!strcasecmp(value, "ao"))                                                                              \
                appConfig.name = SECURITY_MODE_AO;                                                                     \
            if (!strcasecmp(value, "ae"))                                                                              \
                appConfig.name = SECURITY_MODE_AE;                                                                     \
        }                                                                                                              \
    } while (0)

#define CONFIG_STORE_SECURITY_ALGORITHM_PARAM(name)                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if (!strcmp(key, #name))                                                                                       \
        {                                                                                                              \
            if (strcasecmp(value, "aes256-gcm") && strcasecmp(value, "aes128-gcm") &&                                  \
                strcasecmp(value, "chacha20-poly1305"))                                                                \
            {                                                                                                          \
                fprintf(stderr, "Invalid security algorithm specified!\n");                                            \
                goto err_parse;                                                                                        \
            }                                                                                                          \
            if (!strcasecmp(value, "aes256-gcm"))                                                                      \
                appConfig.name = SECURITY_ALGORITHM_AES256_GCM;                                                        \
            if (!strcasecmp(value, "aes128-gcm"))                                                                      \
                appConfig.name = SECURITY_ALGORITHM_AES128_GCM;                                                        \
            if (!strcasecmp(value, "chacha20-poly1305"))                                                               \
                appConfig.name = SECURITY_ALGORITHM_CHACHA20_POLY1305;                                                 \
        }                                                                                                              \
    } while (0)

#define CONFIG_IS_TRAFFIC_CLASS_ACTIVE(name)                                                                           \
    ({                                                                                                                 \
        bool __ret = false;                                                                                            \
        if (appConfig.name##NumFramesPerCycle)                                                                         \
            __ret = true;                                                                                              \
        __ret;                                                                                                         \
    })

static inline bool ConfigHaveBusyPoll(void)
{
#if defined(HAVE_SO_BUSY_POLL) && defined(HAVE_SO_PREFER_BUSY_POLL) && defined(HAVE_SO_BUSY_POLL_BUDGET)
    return true;
#else
    return false;
#endif
}

#endif /* _CONFIG_H_ */
