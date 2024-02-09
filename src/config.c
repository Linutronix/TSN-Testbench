// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2023 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

#include <linux/if_ether.h>

#include "config.h"
#include "net_def.h"
#include "security.h"
#include "utils.h"

#include "dcp_thread.h"
#include "layer2_thread.h"
#include "lldp_thread.h"
#include "rta_thread.h"
#include "rtc_thread.h"
#include "tsn_thread.h"
#include "udp_thread.h"

struct ApplicationConfig appConfig;

/*
 * The configuration file is YAML based. Use libyaml to parse it.
 */
int ConfigReadFromFile(const char *configFile)
{
    int ret, state_key = 0;
    yaml_parser_t parser;
    yaml_token_t token;
    const char *value;
    char *key = NULL;
    FILE *f;

    if (!configFile)
        return -EINVAL;

    f = fopen(configFile, "r");
    if (!f)
    {
        perror("fopen() failed");
        return -EIO;
    }

    ret = yaml_parser_initialize(&parser);
    if (!ret)
    {
        ret = -EINVAL;
        fprintf(stderr, "Failed to initialize YAML parser\n");
        goto err_yaml;
    }

    yaml_parser_set_input_file(&parser, f);

    do
    {
        char *endptr;

        ret = yaml_parser_scan(&parser, &token);
        if (!ret)
        {
            ret = -EINVAL;
            fprintf(stderr, "Failed to parse YAML file!\n");
            goto err_parse;
        }

        switch (token.type)
        {
        case YAML_KEY_TOKEN:
            state_key = 1;
            break;
        case YAML_VALUE_TOKEN:
            state_key = 0;
            break;
        case YAML_SCALAR_TOKEN:
            value = (const char *)token.data.scalar.value;
            if (state_key)
            {
                /* Save key */
                key = strdup(value);
                if (!key)
                {
                    fprintf(stderr, "No memory left!\n");
                    goto err_parse;
                }

                continue;
            }

            /* Switch value */
            CONFIG_STORE_CLOCKID_PARAM(ApplicationClockId);
            CONFIG_STORE_ULONG_PARAM(ApplicationBaseCycleTimeNS);
            CONFIG_STORE_ULONG_PARAM(ApplicationBaseStartTimeNS);
            CONFIG_STORE_ULONG_PARAM(ApplicationTxBaseOffsetNS);
            CONFIG_STORE_ULONG_PARAM(ApplicationRxBaseOffsetNS);
            CONFIG_STORE_STRING_PARAM(ApplicationXdpProgram);

            CONFIG_STORE_BOOL_PARAM(TsnHighTxEnabled);
            CONFIG_STORE_BOOL_PARAM(TsnHighRxEnabled);
            CONFIG_STORE_BOOL_PARAM(TsnHighXdpEnabled);
            CONFIG_STORE_BOOL_PARAM(TsnHighXdpSkbMode);
            CONFIG_STORE_BOOL_PARAM(TsnHighXdpZcMode);
            CONFIG_STORE_BOOL_PARAM(TsnHighXdpWakeupMode);
            CONFIG_STORE_BOOL_PARAM(TsnHighXdpBusyPollMode);
            CONFIG_STORE_BOOL_PARAM(TsnHighTxTimeEnabled);
            CONFIG_STORE_BOOL_PARAM(TsnHighIgnoreRxErrors);
            CONFIG_STORE_ULONG_PARAM(TsnHighTxTimeOffsetNS);
            CONFIG_STORE_INT_PARAM(TsnHighVid);
            CONFIG_STORE_ULONG_PARAM(TsnHighNumFramesPerCycle);
            CONFIG_STORE_STRING_PARAM(TsnHighPayloadPattern);
            CONFIG_STORE_ULONG_PARAM(TsnHighFrameLength);
            CONFIG_STORE_SECURITY_MODE_PARAM(TsnHighSecurityMode);
            CONFIG_STORE_SECURITY_ALGORITHM_PARAM(TsnHighSecurityAlgorithm);
            CONFIG_STORE_STRING_PARAM(TsnHighSecurityKey);
            CONFIG_STORE_STRING_PARAM(TsnHighSecurityIvPrefix);
            CONFIG_STORE_INT_PARAM(TsnHighRxQueue);
            CONFIG_STORE_INT_PARAM(TsnHighTxQueue);
            CONFIG_STORE_INT_PARAM(TsnHighSocketPriority);
            CONFIG_STORE_INT_PARAM(TsnHighTxThreadPriority);
            CONFIG_STORE_INT_PARAM(TsnHighRxThreadPriority);
            CONFIG_STORE_INT_PARAM(TsnHighTxThreadCpu);
            CONFIG_STORE_INT_PARAM(TsnHighRxThreadCpu);
            CONFIG_STORE_INTERFACE_PARAM(TsnHighInterface);
            CONFIG_STORE_MAC_PARAM(TsnHighDestination);

            CONFIG_STORE_BOOL_PARAM(TsnLowTxEnabled);
            CONFIG_STORE_BOOL_PARAM(TsnLowRxEnabled);
            CONFIG_STORE_BOOL_PARAM(TsnLowXdpEnabled);
            CONFIG_STORE_BOOL_PARAM(TsnLowXdpSkbMode);
            CONFIG_STORE_BOOL_PARAM(TsnLowXdpZcMode);
            CONFIG_STORE_BOOL_PARAM(TsnLowXdpWakeupMode);
            CONFIG_STORE_BOOL_PARAM(TsnLowXdpBusyPollMode);
            CONFIG_STORE_BOOL_PARAM(TsnLowTxTimeEnabled);
            CONFIG_STORE_BOOL_PARAM(TsnLowIgnoreRxErrors);
            CONFIG_STORE_ULONG_PARAM(TsnLowTxTimeOffsetNS);
            CONFIG_STORE_INT_PARAM(TsnLowVid);
            CONFIG_STORE_ULONG_PARAM(TsnLowNumFramesPerCycle);
            CONFIG_STORE_STRING_PARAM(TsnLowPayloadPattern);
            CONFIG_STORE_ULONG_PARAM(TsnLowFrameLength);
            CONFIG_STORE_SECURITY_MODE_PARAM(TsnLowSecurityMode);
            CONFIG_STORE_SECURITY_ALGORITHM_PARAM(TsnLowSecurityAlgorithm);
            CONFIG_STORE_STRING_PARAM(TsnLowSecurityKey);
            CONFIG_STORE_STRING_PARAM(TsnLowSecurityIvPrefix);
            CONFIG_STORE_INT_PARAM(TsnLowRxQueue);
            CONFIG_STORE_INT_PARAM(TsnLowTxQueue);
            CONFIG_STORE_INT_PARAM(TsnLowSocketPriority);
            CONFIG_STORE_INT_PARAM(TsnLowTxThreadPriority);
            CONFIG_STORE_INT_PARAM(TsnLowRxThreadPriority);
            CONFIG_STORE_INT_PARAM(TsnLowTxThreadCpu);
            CONFIG_STORE_INT_PARAM(TsnLowRxThreadCpu);
            CONFIG_STORE_INTERFACE_PARAM(TsnLowInterface);
            CONFIG_STORE_MAC_PARAM(TsnLowDestination);

            CONFIG_STORE_BOOL_PARAM(RtcTxEnabled);
            CONFIG_STORE_BOOL_PARAM(RtcRxEnabled);
            CONFIG_STORE_BOOL_PARAM(RtcXdpEnabled);
            CONFIG_STORE_BOOL_PARAM(RtcXdpSkbMode);
            CONFIG_STORE_BOOL_PARAM(RtcXdpZcMode);
            CONFIG_STORE_BOOL_PARAM(RtcXdpWakeupMode);
            CONFIG_STORE_BOOL_PARAM(RtcXdpBusyPollMode);
            CONFIG_STORE_BOOL_PARAM(RtcIgnoreRxErrors);
            CONFIG_STORE_INT_PARAM(RtcVid);
            CONFIG_STORE_ULONG_PARAM(RtcNumFramesPerCycle);
            CONFIG_STORE_STRING_PARAM(RtcPayloadPattern);
            CONFIG_STORE_ULONG_PARAM(RtcFrameLength);
            CONFIG_STORE_SECURITY_MODE_PARAM(RtcSecurityMode);
            CONFIG_STORE_SECURITY_ALGORITHM_PARAM(RtcSecurityAlgorithm);
            CONFIG_STORE_STRING_PARAM(RtcSecurityKey);
            CONFIG_STORE_STRING_PARAM(RtcSecurityIvPrefix);
            CONFIG_STORE_INT_PARAM(RtcRxQueue);
            CONFIG_STORE_INT_PARAM(RtcTxQueue);
            CONFIG_STORE_INT_PARAM(RtcSocketPriority);
            CONFIG_STORE_INT_PARAM(RtcTxThreadPriority);
            CONFIG_STORE_INT_PARAM(RtcRxThreadPriority);
            CONFIG_STORE_INT_PARAM(RtcTxThreadCpu);
            CONFIG_STORE_INT_PARAM(RtcRxThreadCpu);
            CONFIG_STORE_INTERFACE_PARAM(RtcInterface);
            CONFIG_STORE_MAC_PARAM(RtcDestination);

            CONFIG_STORE_BOOL_PARAM(RtaTxEnabled);
            CONFIG_STORE_BOOL_PARAM(RtaRxEnabled);
            CONFIG_STORE_BOOL_PARAM(RtaTxGenEnabled);
            CONFIG_STORE_BOOL_PARAM(RtaXdpEnabled);
            CONFIG_STORE_BOOL_PARAM(RtaXdpSkbMode);
            CONFIG_STORE_BOOL_PARAM(RtaXdpZcMode);
            CONFIG_STORE_BOOL_PARAM(RtaXdpWakeupMode);
            CONFIG_STORE_BOOL_PARAM(RtaXdpBusyPollMode);
            CONFIG_STORE_BOOL_PARAM(RtaIgnoreRxErrors);
            CONFIG_STORE_INT_PARAM(RtaVid);
            CONFIG_STORE_ULONG_PARAM(RtaBurstPeriodNS);
            CONFIG_STORE_ULONG_PARAM(RtaNumFramesPerCycle);
            CONFIG_STORE_STRING_PARAM(RtaPayloadPattern);
            CONFIG_STORE_ULONG_PARAM(RtaFrameLength);
            CONFIG_STORE_SECURITY_MODE_PARAM(RtaSecurityMode);
            CONFIG_STORE_SECURITY_ALGORITHM_PARAM(RtaSecurityAlgorithm);
            CONFIG_STORE_STRING_PARAM(RtaSecurityKey);
            CONFIG_STORE_STRING_PARAM(RtaSecurityIvPrefix);
            CONFIG_STORE_INT_PARAM(RtaRxQueue);
            CONFIG_STORE_INT_PARAM(RtaTxQueue);
            CONFIG_STORE_INT_PARAM(RtaSocketPriority);
            CONFIG_STORE_INT_PARAM(RtaTxThreadPriority);
            CONFIG_STORE_INT_PARAM(RtaRxThreadPriority);
            CONFIG_STORE_INT_PARAM(RtaTxThreadCpu);
            CONFIG_STORE_INT_PARAM(RtaRxThreadCpu);
            CONFIG_STORE_INTERFACE_PARAM(RtaInterface);
            CONFIG_STORE_MAC_PARAM(RtaDestination);

            CONFIG_STORE_BOOL_PARAM(DcpTxEnabled);
            CONFIG_STORE_BOOL_PARAM(DcpRxEnabled);
            CONFIG_STORE_BOOL_PARAM(DcpTxGenEnabled);
            CONFIG_STORE_BOOL_PARAM(DcpIgnoreRxErrors);
            CONFIG_STORE_INT_PARAM(DcpVid);
            CONFIG_STORE_ULONG_PARAM(DcpBurstPeriodNS);
            CONFIG_STORE_ULONG_PARAM(DcpNumFramesPerCycle);
            CONFIG_STORE_STRING_PARAM(DcpPayloadPattern);
            CONFIG_STORE_ULONG_PARAM(DcpFrameLength);
            CONFIG_STORE_INT_PARAM(DcpRxQueue);
            CONFIG_STORE_INT_PARAM(DcpTxQueue);
            CONFIG_STORE_INT_PARAM(DcpSocketPriority);
            CONFIG_STORE_INT_PARAM(DcpTxThreadPriority);
            CONFIG_STORE_INT_PARAM(DcpRxThreadPriority);
            CONFIG_STORE_INT_PARAM(DcpTxThreadCpu);
            CONFIG_STORE_INT_PARAM(DcpRxThreadCpu);
            CONFIG_STORE_INTERFACE_PARAM(DcpInterface);
            CONFIG_STORE_MAC_PARAM(DcpDestination);

            CONFIG_STORE_BOOL_PARAM(LldpTxEnabled);
            CONFIG_STORE_BOOL_PARAM(LldpRxEnabled);
            CONFIG_STORE_BOOL_PARAM(LldpTxGenEnabled);
            CONFIG_STORE_BOOL_PARAM(LldpIgnoreRxErrors);
            CONFIG_STORE_ULONG_PARAM(LldpBurstPeriodNS);
            CONFIG_STORE_ULONG_PARAM(LldpNumFramesPerCycle);
            CONFIG_STORE_STRING_PARAM(LldpPayloadPattern);
            CONFIG_STORE_ULONG_PARAM(LldpFrameLength);
            CONFIG_STORE_INT_PARAM(LldpRxQueue);
            CONFIG_STORE_INT_PARAM(LldpTxQueue);
            CONFIG_STORE_INT_PARAM(LldpSocketPriority);
            CONFIG_STORE_INT_PARAM(LldpTxThreadPriority);
            CONFIG_STORE_INT_PARAM(LldpRxThreadPriority);
            CONFIG_STORE_INT_PARAM(LldpTxThreadCpu);
            CONFIG_STORE_INT_PARAM(LldpRxThreadCpu);
            CONFIG_STORE_INTERFACE_PARAM(LldpInterface);
            CONFIG_STORE_MAC_PARAM(LldpDestination);

            CONFIG_STORE_BOOL_PARAM(UdpHighTxEnabled);
            CONFIG_STORE_BOOL_PARAM(UdpHighRxEnabled);
            CONFIG_STORE_BOOL_PARAM(UdpHighTxGenEnabled);
            CONFIG_STORE_BOOL_PARAM(UdpHighIgnoreRxErrors);
            CONFIG_STORE_ULONG_PARAM(UdpHighBurstPeriodNS);
            CONFIG_STORE_ULONG_PARAM(UdpHighNumFramesPerCycle);
            CONFIG_STORE_STRING_PARAM(UdpHighPayloadPattern);
            CONFIG_STORE_ULONG_PARAM(UdpHighFrameLength);
            CONFIG_STORE_INT_PARAM(UdpHighRxQueue);
            CONFIG_STORE_INT_PARAM(UdpHighTxQueue);
            CONFIG_STORE_INT_PARAM(UdpHighSocketPriority);
            CONFIG_STORE_INT_PARAM(UdpHighTxThreadPriority);
            CONFIG_STORE_INT_PARAM(UdpHighRxThreadPriority);
            CONFIG_STORE_INT_PARAM(UdpHighTxThreadCpu);
            CONFIG_STORE_INT_PARAM(UdpHighRxThreadCpu);
            CONFIG_STORE_INTERFACE_PARAM(UdpHighInterface);
            CONFIG_STORE_STRING_PARAM(UdpHighPort);
            CONFIG_STORE_STRING_PARAM(UdpHighDestination);
            CONFIG_STORE_STRING_PARAM(UdpHighSource);

            CONFIG_STORE_BOOL_PARAM(UdpLowTxEnabled);
            CONFIG_STORE_BOOL_PARAM(UdpLowRxEnabled);
            CONFIG_STORE_BOOL_PARAM(UdpLowTxGenEnabled);
            CONFIG_STORE_BOOL_PARAM(UdpLowIgnoreRxErrors);
            CONFIG_STORE_ULONG_PARAM(UdpLowBurstPeriodNS);
            CONFIG_STORE_ULONG_PARAM(UdpLowNumFramesPerCycle);
            CONFIG_STORE_STRING_PARAM(UdpLowPayloadPattern);
            CONFIG_STORE_ULONG_PARAM(UdpLowFrameLength);
            CONFIG_STORE_INT_PARAM(UdpLowRxQueue);
            CONFIG_STORE_INT_PARAM(UdpLowTxQueue);
            CONFIG_STORE_INT_PARAM(UdpLowSocketPriority);
            CONFIG_STORE_INT_PARAM(UdpLowTxThreadPriority);
            CONFIG_STORE_INT_PARAM(UdpLowRxThreadPriority);
            CONFIG_STORE_INT_PARAM(UdpLowTxThreadCpu);
            CONFIG_STORE_INT_PARAM(UdpLowRxThreadCpu);
            CONFIG_STORE_INTERFACE_PARAM(UdpLowInterface);
            CONFIG_STORE_STRING_PARAM(UdpLowPort);
            CONFIG_STORE_STRING_PARAM(UdpLowDestination);
            CONFIG_STORE_STRING_PARAM(UdpLowSource);

            CONFIG_STORE_STRING_PARAM(GenericL2Name);
            CONFIG_STORE_BOOL_PARAM(GenericL2TxEnabled);
            CONFIG_STORE_BOOL_PARAM(GenericL2RxEnabled);
            CONFIG_STORE_BOOL_PARAM(GenericL2XdpEnabled);
            CONFIG_STORE_BOOL_PARAM(GenericL2XdpSkbMode);
            CONFIG_STORE_BOOL_PARAM(GenericL2XdpZcMode);
            CONFIG_STORE_BOOL_PARAM(GenericL2XdpWakeupMode);
            CONFIG_STORE_BOOL_PARAM(GenericL2XdpBusyPollMode);
            CONFIG_STORE_BOOL_PARAM(GenericL2TxTimeEnabled);
            CONFIG_STORE_BOOL_PARAM(GenericL2IgnoreRxErrors);
            CONFIG_STORE_ULONG_PARAM(GenericL2TxTimeOffsetNS);
            CONFIG_STORE_INT_PARAM(GenericL2Vid);
            CONFIG_STORE_INT_PARAM(GenericL2Pcp);
            CONFIG_STORE_ETHER_TYPE(GenericL2EtherType);
            CONFIG_STORE_ULONG_PARAM(GenericL2NumFramesPerCycle);
            CONFIG_STORE_STRING_PARAM(GenericL2PayloadPattern);
            CONFIG_STORE_ULONG_PARAM(GenericL2FrameLength);
            CONFIG_STORE_INT_PARAM(GenericL2RxQueue);
            CONFIG_STORE_INT_PARAM(GenericL2TxQueue);
            CONFIG_STORE_INT_PARAM(GenericL2SocketPriority);
            CONFIG_STORE_INT_PARAM(GenericL2TxThreadPriority);
            CONFIG_STORE_INT_PARAM(GenericL2RxThreadPriority);
            CONFIG_STORE_INT_PARAM(GenericL2TxThreadCpu);
            CONFIG_STORE_INT_PARAM(GenericL2RxThreadCpu);
            CONFIG_STORE_INTERFACE_PARAM(GenericL2Interface);
            CONFIG_STORE_MAC_PARAM(GenericL2Destination);

            CONFIG_STORE_ULONG_PARAM(LogThreadPeriodNS);
            CONFIG_STORE_INT_PARAM(LogThreadPriority);
            CONFIG_STORE_INT_PARAM(LogThreadCpu);
            CONFIG_STORE_STRING_PARAM(LogFile);
            CONFIG_STORE_STRING_PARAM(LogLevel);

            CONFIG_STORE_BOOL_PARAM(DebugStopTraceOnRtt);
            CONFIG_STORE_BOOL_PARAM(DebugStopTraceOnError);
            CONFIG_STORE_ULONG_PARAM(DebugStopTraceRttLimitNS);
            CONFIG_STORE_BOOL_PARAM(DebugMonitorMode);
            CONFIG_STORE_MAC_PARAM(DebugMonitorDestination);

            CONFIG_STORE_ULONG_PARAM(StatsCollectionIntervalNS);

            CONFIG_STORE_BOOL_PARAM(LogViaMQTT);
            CONFIG_STORE_INT_PARAM(LogViaMQTTThreadPriority);
            CONFIG_STORE_INT_PARAM(LogViaMQTTThreadCpu);
            CONFIG_STORE_ULONG_PARAM(LogViaMQTTThreadPeriodNS);
            CONFIG_STORE_STRING_PARAM(LogViaMQTTBrokerIP);
            CONFIG_STORE_INT_PARAM(LogViaMQTTBrokerPort);
            CONFIG_STORE_INT_PARAM(LogViaMQTTKeepAliveSecs);
            CONFIG_STORE_STRING_PARAM(LogViaMQTTMeasurementName);

            if (key)
                free(key);

        default:
            break;
        }

        if (token.type != YAML_STREAM_END_TOKEN)
            yaml_token_delete(&token);

    } while (token.type != YAML_STREAM_END_TOKEN);

    ret = 0;

err_parse:
    yaml_token_delete(&token);
    yaml_parser_delete(&parser);

err_yaml:
    fclose(f);

    return ret;
}

void ConfigPrintValues(void)
{
    printf("--------------------------------------------------------------------------------\n");
    printf("ApplicationClockId=%s\n", appConfig.ApplicationClockId == CLOCK_TAI ? "CLOCK_TAI" : "CLOCK_MONOTONIC");
    printf("ApplicationBaseCycleTimeNS=%" PRIu64 "\n", appConfig.ApplicationBaseCycleTimeNS);
    printf("ApplicationBaseStartTimeNS=%" PRIu64 "\n", appConfig.ApplicationBaseStartTimeNS);
    printf("ApplicationTxBaseOffsetNS=%" PRIu64 "\n", appConfig.ApplicationTxBaseOffsetNS);
    printf("ApplicationRxBaseOffsetNS=%" PRIu64 "\n", appConfig.ApplicationRxBaseOffsetNS);
    printf("ApplicationXdpProgram=%s\n", appConfig.ApplicationXdpProgram);
    printf("--------------------------------------------------------------------------------\n");
    printf("TsnHighTxEnabled=%s\n", appConfig.TsnHighTxEnabled ? "True" : "False");
    printf("TsnHighRxEnabled=%s\n", appConfig.TsnHighRxEnabled ? "True" : "False");
    printf("TsnHighRxMirrorEnabled=%s\n", appConfig.TsnHighRxMirrorEnabled ? "True" : "False");
    printf("TsnHighXdpEnabled=%s\n", appConfig.TsnHighXdpEnabled ? "True" : "False");
    printf("TsnHighXdpSkbMode=%s\n", appConfig.TsnHighXdpSkbMode ? "True" : "False");
    printf("TsnHighXdpZcMode=%s\n", appConfig.TsnHighXdpZcMode ? "True" : "False");
    printf("TsnHighXdpWakeupMode=%s\n", appConfig.TsnHighXdpWakeupMode ? "True" : "False");
    printf("TsnHighXdpBusyPollMode=%s\n", appConfig.TsnHighXdpBusyPollMode ? "True" : "False");
    printf("TsnHighTxTimeEnabled=%s\n", appConfig.TsnHighTxTimeEnabled ? "True" : "False");
    printf("TsnHighIgnoreRxErrors=%s\n", appConfig.TsnHighIgnoreRxErrors ? "True" : "False");
    printf("TsnHighTxTimeOffsetNS=%" PRIu64 "\n", appConfig.TsnHighTxTimeOffsetNS);
    printf("TsnHighVid=%d\n", appConfig.TsnHighVid);
    printf("TsnHighNumFramesPerCycle=%zu\n", appConfig.TsnHighNumFramesPerCycle);
    printf("TsnHighPayloadPattern=");
    PrintPayloadPattern(appConfig.TsnHighPayloadPattern, appConfig.TsnHighPayloadPatternLength);
    printf("\n");
    printf("TsnHighFrameLength=%zu\n", appConfig.TsnHighFrameLength);
    printf("TsnHighSecurityMode=%s\n", SecurityModeToString(appConfig.TsnHighSecurityMode));
    printf("TsnHighSecurityAlgorithm=%s\n", SecurityAlgorithmToString(appConfig.TsnHighSecurityAlgorithm));
    printf("TsnHighSecurityKey=%s\n", appConfig.TsnHighSecurityKey);
    printf("TsnHighSecurityIvPrefix=%s\n", appConfig.TsnHighSecurityIvPrefix);
    printf("TsnHighRxQueue=%d\n", appConfig.TsnHighRxQueue);
    printf("TsnHighTxQueue=%d\n", appConfig.TsnHighTxQueue);
    printf("TsnHighSocketPriority=%d\n", appConfig.TsnHighSocketPriority);
    printf("TsnHighTxThreadPriority=%d\n", appConfig.TsnHighTxThreadPriority);
    printf("TsnHighRxThreadPriority=%d\n", appConfig.TsnHighRxThreadPriority);
    printf("TsnHighTxThreadCpu=%d\n", appConfig.TsnHighTxThreadCpu);
    printf("TsnHighRxThreadCpu=%d\n", appConfig.TsnHighRxThreadCpu);
    printf("TsnHighInterface=%s\n", appConfig.TsnHighInterface);
    printf("TsnHighDestination=");
    PrintMacAddress(appConfig.TsnHighDestination);
    printf("\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("TsnLowTxEnabled=%s\n", appConfig.TsnLowTxEnabled ? "True" : "False");
    printf("TsnLowRxEnabled=%s\n", appConfig.TsnLowRxEnabled ? "True" : "False");
    printf("TsnLowRxMirrorEnabled=%s\n", appConfig.TsnLowRxMirrorEnabled ? "True" : "False");
    printf("TsnLowXdpEnabled=%s\n", appConfig.TsnLowXdpEnabled ? "True" : "False");
    printf("TsnLowXdpSkbMode=%s\n", appConfig.TsnLowXdpSkbMode ? "True" : "False");
    printf("TsnLowXdpZcMode=%s\n", appConfig.TsnLowXdpZcMode ? "True" : "False");
    printf("TsnLowXdpWakeupMode=%s\n", appConfig.TsnLowXdpWakeupMode ? "True" : "False");
    printf("TsnLowXdpBusyPollMode=%s\n", appConfig.TsnLowXdpBusyPollMode ? "True" : "False");
    printf("TsnLowTxTimeEnabled=%s\n", appConfig.TsnLowTxTimeEnabled ? "True" : "False");
    printf("TsnLowIgnoreRxErrors=%s\n", appConfig.TsnLowIgnoreRxErrors ? "True" : "False");
    printf("TsnLowTxTimeOffsetNS=%" PRIu64 "\n", appConfig.TsnLowTxTimeOffsetNS);
    printf("TsnLowVid=%d\n", appConfig.TsnLowVid);
    printf("TsnLowNumFramesPerCycle=%zu\n", appConfig.TsnLowNumFramesPerCycle);
    printf("TsnLowPayloadPattern=");
    PrintPayloadPattern(appConfig.TsnLowPayloadPattern, appConfig.TsnLowPayloadPatternLength);
    printf("\n");
    printf("TsnLowFrameLength=%zu\n", appConfig.TsnLowFrameLength);
    printf("TsnLowSecurityMode=%s\n", SecurityModeToString(appConfig.TsnLowSecurityMode));
    printf("TsnLowSecurityAlgorithm=%s\n", SecurityAlgorithmToString(appConfig.TsnLowSecurityAlgorithm));
    printf("TsnLowSecurityKey=%s\n", appConfig.TsnLowSecurityKey);
    printf("TsnLowSecurityIvPrefix=%s\n", appConfig.TsnLowSecurityIvPrefix);
    printf("TsnLowRxQueue=%d\n", appConfig.TsnLowRxQueue);
    printf("TsnLowTxQueue=%d\n", appConfig.TsnLowTxQueue);
    printf("TsnLowSocketPriority=%d\n", appConfig.TsnLowSocketPriority);
    printf("TsnLowTxThreadPriority=%d\n", appConfig.TsnLowTxThreadPriority);
    printf("TsnLowRxThreadPriority=%d\n", appConfig.TsnLowRxThreadPriority);
    printf("TsnLowTxThreadCpu=%d\n", appConfig.TsnLowTxThreadCpu);
    printf("TsnLowRxThreadCpu=%d\n", appConfig.TsnLowRxThreadCpu);
    printf("TsnLowInterface=%s\n", appConfig.TsnLowInterface);
    printf("TsnLowDestination=");
    PrintMacAddress(appConfig.TsnLowDestination);
    printf("\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("RtcTxEnabled=%s\n", appConfig.RtcTxEnabled ? "True" : "False");
    printf("RtcRxEnabled=%s\n", appConfig.RtcRxEnabled ? "True" : "False");
    printf("RtcRxMirrorEnabled=%s\n", appConfig.RtcRxMirrorEnabled ? "True" : "False");
    printf("RtcXdpEnabled=%s\n", appConfig.RtcXdpEnabled ? "True" : "False");
    printf("RtcXdpSkbMode=%s\n", appConfig.RtcXdpSkbMode ? "True" : "False");
    printf("RtcXdpZcMode=%s\n", appConfig.RtcXdpZcMode ? "True" : "False");
    printf("RtcXdpWakeupMode=%s\n", appConfig.RtcXdpWakeupMode ? "True" : "False");
    printf("RtcXdpBusyPollMode=%s\n", appConfig.RtcXdpBusyPollMode ? "True" : "False");
    printf("RtcIgnoreRxErrors=%s\n", appConfig.RtcIgnoreRxErrors ? "True" : "False");
    printf("RtcVid=%d\n", appConfig.RtcVid);
    printf("RtcNumFramesPerCycle=%zu\n", appConfig.RtcNumFramesPerCycle);
    printf("RtcPayloadPattern=");
    PrintPayloadPattern(appConfig.RtcPayloadPattern, appConfig.RtcPayloadPatternLength);
    printf("\n");
    printf("RtcFrameLength=%zu\n", appConfig.RtcFrameLength);
    printf("RtcSecurityMode=%s\n", SecurityModeToString(appConfig.RtcSecurityMode));
    printf("RtcSecurityAlgorithm=%s\n", SecurityAlgorithmToString(appConfig.RtcSecurityAlgorithm));
    printf("RtcSecurityKey=%s\n", appConfig.RtcSecurityKey);
    printf("RtcSecurityIvPrefix=%s\n", appConfig.RtcSecurityIvPrefix);
    printf("RtcRxQueue=%d\n", appConfig.RtcRxQueue);
    printf("RtcTxQueue=%d\n", appConfig.RtcTxQueue);
    printf("RtcSocketPriority=%d\n", appConfig.RtcSocketPriority);
    printf("RtcTxThreadPriority=%d\n", appConfig.RtcTxThreadPriority);
    printf("RtcRxThreadPriority=%d\n", appConfig.RtcRxThreadPriority);
    printf("RtcTxThreadCpu=%d\n", appConfig.RtcTxThreadCpu);
    printf("RtcRxThreadCpu=%d\n", appConfig.RtcRxThreadCpu);
    printf("RtcInterface=%s\n", appConfig.RtcInterface);
    printf("RtcDestination=");
    PrintMacAddress(appConfig.RtcDestination);
    printf("\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("RtaTxEnabled=%s\n", appConfig.RtaTxEnabled ? "True" : "False");
    printf("RtaRxEnabled=%s\n", appConfig.RtaRxEnabled ? "True" : "False");
    printf("RtaTxGenEnabled=%s\n", appConfig.RtaTxGenEnabled ? "True" : "False");
    printf("RtaRxMirrorEnabled=%s\n", appConfig.RtaRxMirrorEnabled ? "True" : "False");
    printf("RtaXdpEnabled=%s\n", appConfig.RtaXdpEnabled ? "True" : "False");
    printf("RtaXdpSkbMode=%s\n", appConfig.RtaXdpSkbMode ? "True" : "False");
    printf("RtaXdpZcMode=%s\n", appConfig.RtaXdpZcMode ? "True" : "False");
    printf("RtaXdpWakeupMode=%s\n", appConfig.RtaXdpWakeupMode ? "True" : "False");
    printf("RtaXdpBusyPollMode=%s\n", appConfig.RtaXdpBusyPollMode ? "True" : "False");
    printf("RtaIgnoreRxErrors=%s\n", appConfig.RtaIgnoreRxErrors ? "True" : "False");
    printf("RtaVid=%d\n", appConfig.RtaVid);
    printf("RtaBurstPeriodNS=%" PRIu64 "\n", appConfig.RtaBurstPeriodNS);
    printf("RtaNumFramesPerCycle=%zu\n", appConfig.RtaNumFramesPerCycle);
    printf("RtaPayloadPattern=");
    PrintPayloadPattern(appConfig.RtaPayloadPattern, appConfig.RtaPayloadPatternLength);
    printf("\n");
    printf("RtaFrameLength=%zu\n", appConfig.RtaFrameLength);
    printf("RtaSecurityMode=%s\n", SecurityModeToString(appConfig.RtaSecurityMode));
    printf("RtaSecurityAlgorithm=%s\n", SecurityAlgorithmToString(appConfig.RtaSecurityAlgorithm));
    printf("RtaSecurityKey=%s\n", appConfig.RtaSecurityKey);
    printf("RtaSecurityIvPrefix=%s\n", appConfig.RtaSecurityIvPrefix);
    printf("RtaRxQueue=%d\n", appConfig.RtaRxQueue);
    printf("RtaTxQueue=%d\n", appConfig.RtaTxQueue);
    printf("RtaSocketPriority=%d\n", appConfig.RtaSocketPriority);
    printf("RtaTxThreadPriority=%d\n", appConfig.RtaTxThreadPriority);
    printf("RtaRxThreadPriority=%d\n", appConfig.RtaRxThreadPriority);
    printf("RtaTxThreadCpu=%d\n", appConfig.RtaTxThreadCpu);
    printf("RtaRxThreadCpu=%d\n", appConfig.RtaRxThreadCpu);
    printf("RtaInterface=%s\n", appConfig.RtaInterface);
    printf("RtaDestination=");
    PrintMacAddress(appConfig.RtaDestination);
    printf("\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("DcpTxEnabled=%s\n", appConfig.DcpTxEnabled ? "True" : "False");
    printf("DcpRxEnabled=%s\n", appConfig.DcpRxEnabled ? "True" : "False");
    printf("DcpTxGenEnabled=%s\n", appConfig.DcpTxGenEnabled ? "True" : "False");
    printf("DcpRxMirrorEnabled=%s\n", appConfig.DcpRxMirrorEnabled ? "True" : "False");
    printf("DcpIgnoreRxErrors=%s\n", appConfig.DcpIgnoreRxErrors ? "True" : "False");
    printf("DcpVid=%d\n", appConfig.DcpVid);
    printf("DcpBurstPeriodNS=%" PRIu64 "\n", appConfig.DcpBurstPeriodNS);
    printf("DcpNumFramesPerCycle=%zu\n", appConfig.DcpNumFramesPerCycle);
    printf("DcpPayloadPattern=");
    PrintPayloadPattern(appConfig.DcpPayloadPattern, appConfig.DcpPayloadPatternLength);
    printf("\n");
    printf("DcpFrameLength=%zu\n", appConfig.DcpFrameLength);
    printf("DcpRxQueue=%d\n", appConfig.DcpRxQueue);
    printf("DcpTxQueue=%d\n", appConfig.DcpTxQueue);
    printf("DcpSocketPriority=%d\n", appConfig.DcpSocketPriority);
    printf("DcpTxThreadPriority=%d\n", appConfig.DcpTxThreadPriority);
    printf("DcpRxThreadPriority=%d\n", appConfig.DcpRxThreadPriority);
    printf("DcpTxThreadCpu=%d\n", appConfig.DcpTxThreadCpu);
    printf("DcpRxThreadCpu=%d\n", appConfig.DcpRxThreadCpu);
    printf("DcpInterface=%s\n", appConfig.DcpInterface);
    printf("DcpDestination=");
    PrintMacAddress(appConfig.DcpDestination);
    printf("\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("LldpTxEnabled=%s\n", appConfig.LldpTxEnabled ? "True" : "False");
    printf("LldpRxEnabled=%s\n", appConfig.LldpRxEnabled ? "True" : "False");
    printf("LldpTxGenEnabled=%s\n", appConfig.LldpTxGenEnabled ? "True" : "False");
    printf("LldpRxMirrorEnabled=%s\n", appConfig.LldpRxMirrorEnabled ? "True" : "False");
    printf("LldpIgnoreRxErrors=%s\n", appConfig.DcpIgnoreRxErrors ? "True" : "False");
    printf("LldpBurstPeriodNS=%" PRIu64 "\n", appConfig.LldpBurstPeriodNS);
    printf("LldpNumFramesPerCycle=%zu\n", appConfig.LldpNumFramesPerCycle);
    printf("LldpPayloadPattern=");
    PrintPayloadPattern(appConfig.LldpPayloadPattern, appConfig.LldpPayloadPatternLength);
    printf("\n");
    printf("LldpFrameLength=%zu\n", appConfig.LldpFrameLength);
    printf("LldpRxQueue=%d\n", appConfig.LldpRxQueue);
    printf("LldpTxQueue=%d\n", appConfig.LldpTxQueue);
    printf("LldpSocketPriority=%d\n", appConfig.LldpSocketPriority);
    printf("LldpTxThreadPriority=%d\n", appConfig.LldpTxThreadPriority);
    printf("LldpRxThreadPriority=%d\n", appConfig.LldpRxThreadPriority);
    printf("LldpTxThreadCpu=%d\n", appConfig.LldpTxThreadCpu);
    printf("LldpRxThreadCpu=%d\n", appConfig.LldpRxThreadCpu);
    printf("LldpInterface=%s\n", appConfig.LldpInterface);
    printf("LldpDestination=");
    PrintMacAddress(appConfig.LldpDestination);
    printf("\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("UdpHighTxEnabled=%s\n", appConfig.UdpHighTxEnabled ? "True" : "False");
    printf("UdpHighRxEnabled=%s\n", appConfig.UdpHighRxEnabled ? "True" : "False");
    printf("UdpHighTxGenEnabled=%s\n", appConfig.UdpHighTxGenEnabled ? "True" : "False");
    printf("UdpHighRxMirrorEnabled=%s\n", appConfig.UdpHighRxMirrorEnabled ? "True" : "False");
    printf("UdpHighIgnoreRxErrors=%s\n", appConfig.UdpHighIgnoreRxErrors ? "True" : "False");
    printf("UdpHighBurstPeriodNS=%" PRIu64 "\n", appConfig.UdpHighBurstPeriodNS);
    printf("UdpHighNumFramesPerCycle=%zu\n", appConfig.UdpHighNumFramesPerCycle);
    printf("UdpHighPayloadPattern=");
    PrintPayloadPattern(appConfig.UdpHighPayloadPattern, appConfig.UdpHighPayloadPatternLength);
    printf("\n");
    printf("UdpHighFrameLength=%zu\n", appConfig.UdpHighFrameLength);
    printf("UdpHighRxQueue=%d\n", appConfig.UdpHighRxQueue);
    printf("UdpHighTxQueue=%d\n", appConfig.UdpHighTxQueue);
    printf("UdpHighSocketPriority=%d\n", appConfig.UdpHighSocketPriority);
    printf("UdpHighTxThreadPriority=%d\n", appConfig.UdpHighTxThreadPriority);
    printf("UdpHighRxThreadPriority=%d\n", appConfig.UdpHighRxThreadPriority);
    printf("UdpHighTxThreadCpu=%d\n", appConfig.UdpHighTxThreadCpu);
    printf("UdpHighRxThreadCpu=%d\n", appConfig.UdpHighRxThreadCpu);
    printf("UdpHighInterface=%s\n", appConfig.UdpHighInterface);
    printf("UdpHighPort=%s\n", appConfig.UdpHighPort);
    printf("UdpHighDestination=%s\n", appConfig.UdpHighDestination);
    printf("UdpHighSource=%s\n", appConfig.UdpHighSource);
    printf("--------------------------------------------------------------------------------\n");
    printf("UdpLowTxEnabled=%s\n", appConfig.UdpLowTxEnabled ? "True" : "False");
    printf("UdpLowRxEnabled=%s\n", appConfig.UdpLowRxEnabled ? "True" : "False");
    printf("UdpLowTxGenEnabled=%s\n", appConfig.UdpLowTxGenEnabled ? "True" : "False");
    printf("UdpLowRxMirrorEnabled=%s\n", appConfig.UdpLowRxMirrorEnabled ? "True" : "False");
    printf("UdpLowIgnoreRxErrors=%s\n", appConfig.UdpLowIgnoreRxErrors ? "True" : "False");
    printf("UdpLowBurstPeriodNS=%" PRIu64 "\n", appConfig.UdpLowBurstPeriodNS);
    printf("UdpLowNumFramesPerCycle=%zu\n", appConfig.UdpLowNumFramesPerCycle);
    printf("UdpLowPayloadPattern=");
    PrintPayloadPattern(appConfig.UdpLowPayloadPattern, appConfig.UdpLowPayloadPatternLength);
    printf("\n");
    printf("UdpLowFrameLength=%zu\n", appConfig.UdpLowFrameLength);
    printf("UdpLowRxQueue=%d\n", appConfig.UdpLowRxQueue);
    printf("UdpLowTxQueue=%d\n", appConfig.UdpLowTxQueue);
    printf("UdpLowSocketPriority=%d\n", appConfig.UdpLowSocketPriority);
    printf("UdpLowTxThreadPriority=%d\n", appConfig.UdpLowTxThreadPriority);
    printf("UdpLowRxThreadPriority=%d\n", appConfig.UdpLowRxThreadPriority);
    printf("UdpLowTxThreadCpu=%d\n", appConfig.UdpLowTxThreadCpu);
    printf("UdpLowRxThreadCpu=%d\n", appConfig.UdpLowRxThreadCpu);
    printf("UdpLowInterface=%s\n", appConfig.UdpLowInterface);
    printf("UdpLowPort=%s\n", appConfig.UdpLowPort);
    printf("UdpLowDestination=%s\n", appConfig.UdpLowDestination);
    printf("UdpLowSource=%s\n", appConfig.UdpLowSource);
    printf("--------------------------------------------------------------------------------\n");
    printf("GenericL2Name=%s\n", appConfig.GenericL2Name);
    printf("GenericL2TxEnabled=%s\n", appConfig.GenericL2TxEnabled ? "True" : "False");
    printf("GenericL2RxEnabled=%s\n", appConfig.GenericL2RxEnabled ? "True" : "False");
    printf("GenericL2RxMirrorEnabled=%s\n", appConfig.GenericL2RxMirrorEnabled ? "True" : "False");
    printf("GenericL2XdpEnabled=%s\n", appConfig.GenericL2XdpEnabled ? "True" : "False");
    printf("GenericL2XdpSkbMode=%s\n", appConfig.GenericL2XdpSkbMode ? "True" : "False");
    printf("GenericL2XdpZcMode=%s\n", appConfig.GenericL2XdpZcMode ? "True" : "False");
    printf("GenericL2XdpWakeupMode=%s\n", appConfig.GenericL2XdpWakeupMode ? "True" : "False");
    printf("GenericL2XdpBusyPollMode=%s\n", appConfig.GenericL2XdpBusyPollMode ? "True" : "False");
    printf("GenericL2TxTimeEnabled=%s\n", appConfig.GenericL2TxTimeEnabled ? "True" : "False");
    printf("GenericL2IgnoreRxErrors=%s\n", appConfig.GenericL2IgnoreRxErrors ? "True" : "False");
    printf("GenericL2TxTimeOffsetNS=%" PRIu64 "\n", appConfig.GenericL2TxTimeOffsetNS);
    printf("GenericL2Vid=%d\n", appConfig.GenericL2Vid);
    printf("GenericL2Pcp=%d\n", appConfig.GenericL2Pcp);
    printf("GenericL2EtherType=0x%04x\n", appConfig.GenericL2EtherType);
    printf("GenericL2NumFramesPerCycle=%zu\n", appConfig.GenericL2NumFramesPerCycle);
    printf("GenericL2PayloadPattern=");
    PrintPayloadPattern(appConfig.GenericL2PayloadPattern, appConfig.GenericL2PayloadPatternLength);
    printf("\n");
    printf("GenericL2FrameLength=%zu\n", appConfig.GenericL2FrameLength);
    printf("GenericL2RxQueue=%d\n", appConfig.GenericL2RxQueue);
    printf("GenericL2TxQueue=%d\n", appConfig.GenericL2TxQueue);
    printf("GenericL2SocketPriority=%d\n", appConfig.GenericL2SocketPriority);
    printf("GenericL2TxThreadPriority=%d\n", appConfig.GenericL2TxThreadPriority);
    printf("GenericL2RxThreadPriority=%d\n", appConfig.GenericL2RxThreadPriority);
    printf("GenericL2TxThreadCpu=%d\n", appConfig.GenericL2TxThreadCpu);
    printf("GenericL2RxThreadCpu=%d\n", appConfig.GenericL2RxThreadCpu);
    printf("GenericL2Interface=%s\n", appConfig.GenericL2Interface);
    printf("GenericL2Destination=");
    PrintMacAddress(appConfig.GenericL2Destination);
    printf("\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("LogThreadPeriodNS=%" PRIu64 "\n", appConfig.LogThreadPeriodNS);
    printf("LogThreadPriority=%d\n", appConfig.LogThreadPriority);
    printf("LogThreadCpu=%d\n", appConfig.LogThreadCpu);
    printf("LogFile=%s\n", appConfig.LogFile);
    printf("LogLevel=%s\n", appConfig.LogLevel);
    printf("--------------------------------------------------------------------------------\n");
    printf("DebugStopTraceOnRtt=%s\n", appConfig.DebugStopTraceOnRtt ? "True" : "False");
    printf("DebugStopTraceOnError=%s\n", appConfig.DebugStopTraceOnError ? "True" : "False");
    printf("DebugStopTraceLimitNS=%" PRIu64 "\n", appConfig.DebugStopTraceRttLimitNS);
    printf("DebugMonitorMode=%s\n", appConfig.DebugMonitorMode ? "True" : "False");
    printf("DebugMonitorDestination=");
    PrintMacAddress(appConfig.DebugMonitorDestination);
    printf("--------------------------------------------------------------------------------\n");
    printf("StatsCollectionIntervalNS=%ld\n", appConfig.StatsCollectionIntervalNS);
    printf("--------------------------------------------------------------------------------\n");
    printf("LogViaMQTT=%s\n", appConfig.LogViaMQTT ? "True" : "False");
    printf("LogViaMQTTThreadPriority=%d\n", appConfig.LogViaMQTTThreadPriority);
    printf("LogViaMQTTThreadCpu=%d\n", appConfig.LogViaMQTTThreadCpu);
    printf("LogViaMQTTThreadPeriodNS=%ld\n", appConfig.LogViaMQTTThreadPeriodNS);
    printf("LogViaMQTTBrokerIP=%s\n", appConfig.LogViaMQTTBrokerIP);
    printf("LogViaMQTTBrokerPort=%d\n", appConfig.LogViaMQTTBrokerPort);
    printf("LogViaMQTTKeepAliveSecs=%d\n", appConfig.LogViaMQTTKeepAliveSecs);
    printf("LogViaMQTTMeasurementName=%s\n", appConfig.LogViaMQTTMeasurementName);
    printf("\n");
    printf("--------------------------------------------------------------------------------\n");
}

int ConfigSetDefaults(bool mirrorEnabled)
{
    static unsigned char defaultDestination[] = {0xa8, 0xa1, 0x59, 0x2c, 0xa8, 0xdb};
    static unsigned char defaultDcpIdentify[] = {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00};
    static unsigned char defaultLldpDestination[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};
    static unsigned char defaultDebugMontitorDestination[] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
    static const char *DefaultPayloadPattern = "Payload";
    static const char *DefaultUdpLowDestination = "192.168.2.120";
    static const char *DefaultUdpLowSource = "192.168.2.119";
    static const char *DefaultLogLevel = "Debug";
    static const char *DefaultUdpLowPort = "6666";

    static const char *DefaultLogViaMQTTBrokerIP = "127.0.0.1";
    static const char *DefaultLogViaMQTTMeasurementName = "testbench";

    struct timespec current;
    int ret = -ENOMEM;

    clock_gettime(CLOCK_TAI, &current);

    /* Application scheduling configuration */
    appConfig.ApplicationClockId = CLOCK_TAI;
    appConfig.ApplicationBaseCycleTimeNS = 500000;
    appConfig.ApplicationBaseStartTimeNS = (current.tv_sec + 30) * NSEC_PER_SEC;
    appConfig.ApplicationTxBaseOffsetNS = 400000;
    appConfig.ApplicationRxBaseOffsetNS = 200000;
    appConfig.ApplicationXdpProgram = NULL;

    /* TSN High */
    appConfig.TsnHighTxEnabled = false;
    appConfig.TsnHighRxEnabled = false;
    appConfig.TsnHighRxMirrorEnabled = mirrorEnabled;
    appConfig.TsnHighXdpEnabled = false;
    appConfig.TsnHighXdpSkbMode = false;
    appConfig.TsnHighXdpZcMode = false;
    appConfig.TsnHighXdpWakeupMode = true;
    appConfig.TsnHighXdpBusyPollMode = false;
    appConfig.TsnHighTxTimeEnabled = false;
    appConfig.TsnHighIgnoreRxErrors = false;
    appConfig.TsnHighTxTimeOffsetNS = 0;
    appConfig.TsnHighVid = TSN_HIGH_VID_VALUE;
    appConfig.TsnHighNumFramesPerCycle = 0;
    appConfig.TsnHighPayloadPattern = strdup(DefaultPayloadPattern);
    if (!appConfig.TsnHighPayloadPattern)
        goto out;
    appConfig.TsnHighPayloadPatternLength = strlen(appConfig.TsnHighPayloadPattern);
    appConfig.TsnHighFrameLength = 200;
    appConfig.TsnHighSecurityMode = SECURITY_MODE_NONE;
    appConfig.TsnHighSecurityAlgorithm = SECURITY_ALGORITHM_AES256_GCM;
    appConfig.TsnHighSecurityKey = NULL;
    appConfig.TsnHighSecurityIvPrefix = NULL;
    appConfig.TsnHighRxQueue = 1;
    appConfig.TsnHighTxQueue = 1;
    appConfig.TsnHighSocketPriority = 1;
    appConfig.TsnHighTxThreadPriority = 98;
    appConfig.TsnHighRxThreadPriority = 98;
    appConfig.TsnHighTxThreadCpu = 0;
    appConfig.TsnHighRxThreadCpu = 0;
    strncpy(appConfig.TsnHighInterface, "enp3s0", sizeof(appConfig.TsnHighInterface) - 1);
    memcpy((void *)appConfig.TsnHighDestination, defaultDestination, ETH_ALEN);

    /* TSN Low */
    appConfig.TsnLowTxEnabled = false;
    appConfig.TsnLowRxEnabled = false;
    appConfig.TsnLowRxMirrorEnabled = mirrorEnabled;
    appConfig.TsnLowXdpEnabled = false;
    appConfig.TsnLowXdpSkbMode = false;
    appConfig.TsnLowXdpZcMode = false;
    appConfig.TsnLowXdpWakeupMode = true;
    appConfig.TsnLowXdpBusyPollMode = false;
    appConfig.TsnLowTxTimeEnabled = false;
    appConfig.TsnLowIgnoreRxErrors = false;
    appConfig.TsnLowTxTimeOffsetNS = 0;
    appConfig.TsnLowVid = TSN_LOW_VID_VALUE;
    appConfig.TsnLowNumFramesPerCycle = 0;
    appConfig.TsnLowPayloadPattern = strdup(DefaultPayloadPattern);
    if (!appConfig.TsnLowPayloadPattern)
        goto out;
    appConfig.TsnLowPayloadPatternLength = strlen(appConfig.TsnLowPayloadPattern);
    appConfig.TsnLowFrameLength = 200;
    appConfig.TsnLowSecurityMode = SECURITY_MODE_NONE;
    appConfig.TsnLowSecurityAlgorithm = SECURITY_ALGORITHM_AES256_GCM;
    appConfig.TsnLowSecurityKey = NULL;
    appConfig.TsnLowSecurityIvPrefix = NULL;
    appConfig.TsnLowRxQueue = 1;
    appConfig.TsnLowTxQueue = 1;
    appConfig.TsnLowSocketPriority = 1;
    appConfig.TsnLowTxThreadPriority = 98;
    appConfig.TsnLowRxThreadPriority = 98;
    appConfig.TsnLowTxThreadCpu = 0;
    appConfig.TsnLowRxThreadCpu = 0;
    strncpy(appConfig.TsnLowInterface, "enp3s0", sizeof(appConfig.TsnLowInterface) - 1);
    memcpy((void *)appConfig.TsnLowDestination, defaultDestination, ETH_ALEN);

    /* Real Time Cyclic (RTC) */
    appConfig.RtcTxEnabled = false;
    appConfig.RtcRxEnabled = false;
    appConfig.RtcRxMirrorEnabled = mirrorEnabled;
    appConfig.RtcXdpEnabled = false;
    appConfig.RtcXdpSkbMode = false;
    appConfig.RtcXdpZcMode = false;
    appConfig.RtcXdpWakeupMode = true;
    appConfig.RtcXdpBusyPollMode = false;
    appConfig.RtcIgnoreRxErrors = false;
    appConfig.RtcVid = PROFINET_RT_VID_VALUE;
    appConfig.RtcNumFramesPerCycle = 0;
    appConfig.RtcPayloadPattern = strdup(DefaultPayloadPattern);
    if (!appConfig.RtcPayloadPattern)
        goto out;
    appConfig.RtcPayloadPatternLength = strlen(appConfig.RtcPayloadPattern);
    appConfig.RtcFrameLength = 200;
    appConfig.RtcSecurityMode = SECURITY_MODE_NONE;
    appConfig.RtcSecurityAlgorithm = SECURITY_ALGORITHM_AES256_GCM;
    appConfig.RtcSecurityKey = NULL;
    appConfig.RtcSecurityIvPrefix = NULL;
    appConfig.RtcRxQueue = 1;
    appConfig.RtcTxQueue = 1;
    appConfig.RtcSocketPriority = 1;
    appConfig.RtcTxThreadPriority = 98;
    appConfig.RtcRxThreadPriority = 98;
    appConfig.RtcTxThreadCpu = 0;
    appConfig.RtcRxThreadCpu = 0;
    strncpy(appConfig.RtcInterface, "enp3s0", sizeof(appConfig.RtcInterface) - 1);
    memcpy((void *)appConfig.RtcDestination, defaultDestination, ETH_ALEN);

    /* Real Time Acyclic (RTA) */
    appConfig.RtaTxEnabled = false;
    appConfig.RtaRxEnabled = false;
    appConfig.RtaTxGenEnabled = false;
    appConfig.RtaRxMirrorEnabled = mirrorEnabled;
    appConfig.RtaXdpEnabled = false;
    appConfig.RtaXdpSkbMode = false;
    appConfig.RtaXdpZcMode = false;
    appConfig.RtaXdpWakeupMode = true;
    appConfig.RtaXdpBusyPollMode = false;
    appConfig.RtaIgnoreRxErrors = false;
    appConfig.RtaVid = PROFINET_RT_VID_VALUE;
    appConfig.RtaBurstPeriodNS = 200000000;
    appConfig.RtaNumFramesPerCycle = 0;
    appConfig.RtaPayloadPattern = strdup(DefaultPayloadPattern);
    if (!appConfig.RtaPayloadPattern)
        goto out;
    appConfig.RtaPayloadPatternLength = strlen(appConfig.RtaPayloadPattern);
    appConfig.RtaFrameLength = 200;
    appConfig.RtaSecurityMode = SECURITY_MODE_NONE;
    appConfig.RtaSecurityAlgorithm = SECURITY_ALGORITHM_AES256_GCM;
    appConfig.RtaSecurityKey = NULL;
    appConfig.RtaSecurityIvPrefix = NULL;
    appConfig.RtaRxQueue = 1;
    appConfig.RtaTxQueue = 1;
    appConfig.RtaSocketPriority = 1;
    appConfig.RtaTxThreadPriority = 98;
    appConfig.RtaRxThreadPriority = 98;
    appConfig.RtaTxThreadCpu = 0;
    appConfig.RtaRxThreadCpu = 0;
    strncpy(appConfig.RtaInterface, "enp3s0", sizeof(appConfig.RtaInterface) - 1);
    memcpy((void *)appConfig.RtaDestination, defaultDestination, ETH_ALEN);

    /* Discovery and Configuration Protocol (DCP) */
    appConfig.DcpTxEnabled = false;
    appConfig.DcpRxEnabled = false;
    appConfig.DcpTxGenEnabled = false;
    appConfig.DcpIgnoreRxErrors = false;
    appConfig.DcpRxMirrorEnabled = mirrorEnabled;
    appConfig.DcpVid = PROFINET_RT_VID_VALUE;
    appConfig.DcpBurstPeriodNS = 2000000000;
    appConfig.DcpNumFramesPerCycle = 0;
    appConfig.DcpPayloadPattern = strdup(DefaultPayloadPattern);
    if (!appConfig.DcpPayloadPattern)
        goto out;
    appConfig.DcpPayloadPatternLength = strlen(appConfig.DcpPayloadPattern);
    appConfig.DcpFrameLength = 200;
    appConfig.DcpRxQueue = 1;
    appConfig.DcpTxQueue = 1;
    appConfig.DcpSocketPriority = 1;
    appConfig.DcpTxThreadPriority = 98;
    appConfig.DcpRxThreadPriority = 98;
    appConfig.DcpTxThreadCpu = 3;
    appConfig.DcpRxThreadCpu = 3;
    strncpy(appConfig.DcpInterface, "enp3s0", sizeof(appConfig.DcpInterface) - 1);
    memcpy((void *)appConfig.DcpDestination, defaultDcpIdentify, ETH_ALEN);

    /* Link Layer Discovery Protocol (LLDP) */
    appConfig.LldpTxEnabled = false;
    appConfig.LldpRxEnabled = false;
    appConfig.LldpTxGenEnabled = false;
    appConfig.LldpIgnoreRxErrors = false;
    appConfig.LldpRxMirrorEnabled = mirrorEnabled;
    appConfig.LldpBurstPeriodNS = 5000000000;
    appConfig.LldpNumFramesPerCycle = 0;
    appConfig.LldpPayloadPattern = strdup(DefaultPayloadPattern);
    if (!appConfig.LldpPayloadPattern)
        goto out;
    appConfig.LldpPayloadPatternLength = strlen(appConfig.LldpPayloadPattern);
    appConfig.LldpFrameLength = 200;
    appConfig.LldpRxQueue = 1;
    appConfig.LldpTxQueue = 1;
    appConfig.LldpSocketPriority = 1;
    appConfig.LldpTxThreadPriority = 98;
    appConfig.LldpRxThreadPriority = 98;
    appConfig.LldpTxThreadCpu = 4;
    appConfig.LldpRxThreadCpu = 4;
    strncpy(appConfig.LldpInterface, "enp3s0", sizeof(appConfig.LldpInterface) - 1);
    memcpy((void *)appConfig.LldpDestination, defaultLldpDestination, ETH_ALEN);

    /* User Datagram Protocol (UDP) High */
    appConfig.UdpHighTxEnabled = false;
    appConfig.UdpHighRxEnabled = false;
    appConfig.UdpHighTxGenEnabled = false;
    appConfig.UdpHighIgnoreRxErrors = false;
    appConfig.UdpHighRxMirrorEnabled = mirrorEnabled;
    appConfig.UdpHighBurstPeriodNS = 1000000000;
    appConfig.UdpHighNumFramesPerCycle = 0;
    appConfig.UdpHighPayloadPattern = strdup(DefaultPayloadPattern);
    if (!appConfig.UdpHighPayloadPattern)
        goto out;
    appConfig.UdpHighPayloadPatternLength = strlen(appConfig.UdpHighPayloadPattern);
    appConfig.UdpHighFrameLength = 1400;
    appConfig.UdpHighRxQueue = 0;
    appConfig.UdpHighTxQueue = 0;
    appConfig.UdpHighSocketPriority = 0;
    appConfig.UdpHighTxThreadPriority = 98;
    appConfig.UdpHighRxThreadPriority = 98;
    appConfig.UdpHighTxThreadCpu = 5;
    appConfig.UdpHighRxThreadCpu = 5;
    strncpy(appConfig.UdpHighInterface, "enp3s0", sizeof(appConfig.UdpHighInterface) - 1);
    appConfig.UdpHighPort = strdup(DefaultUdpLowPort);
    if (!appConfig.UdpHighPort)
        goto out;
    appConfig.UdpHighDestination = strdup(DefaultUdpLowDestination);
    if (!appConfig.UdpHighDestination)
        goto out;
    appConfig.UdpHighSource = strdup(DefaultUdpLowSource);
    if (!appConfig.UdpHighSource)
        goto out;

    /* User Datagram Protocol (UDP) Low */
    appConfig.UdpLowTxEnabled = false;
    appConfig.UdpLowRxEnabled = false;
    appConfig.UdpLowTxGenEnabled = false;
    appConfig.UdpLowIgnoreRxErrors = false;
    appConfig.UdpLowRxMirrorEnabled = mirrorEnabled;
    appConfig.UdpLowBurstPeriodNS = 1000000000;
    appConfig.UdpLowNumFramesPerCycle = 0;
    appConfig.UdpLowPayloadPattern = strdup(DefaultPayloadPattern);
    if (!appConfig.UdpLowPayloadPattern)
        goto out;
    appConfig.UdpLowPayloadPatternLength = strlen(appConfig.UdpLowPayloadPattern);
    appConfig.UdpLowFrameLength = 1400;
    appConfig.UdpLowRxQueue = 0;
    appConfig.UdpLowTxQueue = 0;
    appConfig.UdpLowSocketPriority = 0;
    appConfig.UdpLowTxThreadPriority = 98;
    appConfig.UdpLowRxThreadPriority = 98;
    appConfig.UdpLowTxThreadCpu = 5;
    appConfig.UdpLowRxThreadCpu = 5;
    strncpy(appConfig.UdpLowInterface, "enp3s0", sizeof(appConfig.UdpLowInterface) - 1);
    appConfig.UdpLowPort = strdup(DefaultUdpLowPort);
    if (!appConfig.UdpLowPort)
        goto out;
    appConfig.UdpLowDestination = strdup(DefaultUdpLowDestination);
    if (!appConfig.UdpLowDestination)
        goto out;
    appConfig.UdpLowSource = strdup(DefaultUdpLowSource);
    if (!appConfig.UdpLowSource)
        goto out;

    /* Generic L2 */
    appConfig.GenericL2Name = strdup("GenericL2");
    if (!appConfig.GenericL2Name)
        goto out;
    appConfig.GenericL2TxEnabled = false;
    appConfig.GenericL2RxEnabled = false;
    appConfig.GenericL2RxMirrorEnabled = mirrorEnabled;
    appConfig.GenericL2XdpEnabled = false;
    appConfig.GenericL2XdpSkbMode = false;
    appConfig.GenericL2XdpZcMode = false;
    appConfig.GenericL2XdpWakeupMode = true;
    appConfig.GenericL2XdpBusyPollMode = false;
    appConfig.GenericL2TxTimeEnabled = false;
    appConfig.GenericL2IgnoreRxErrors = false;
    appConfig.GenericL2TxTimeOffsetNS = 0;
    appConfig.GenericL2Vid = 100;
    appConfig.GenericL2Pcp = 6;
    appConfig.GenericL2EtherType = 0xb62c;
    appConfig.GenericL2NumFramesPerCycle = 0;
    appConfig.GenericL2PayloadPattern = strdup(DefaultPayloadPattern);
    if (!appConfig.GenericL2PayloadPattern)
        goto out;
    appConfig.GenericL2PayloadPatternLength = strlen(appConfig.GenericL2PayloadPattern);
    appConfig.GenericL2FrameLength = 200;
    appConfig.GenericL2RxQueue = 1;
    appConfig.GenericL2TxQueue = 1;
    appConfig.GenericL2SocketPriority = 1;
    appConfig.GenericL2TxThreadPriority = 90;
    appConfig.GenericL2RxThreadPriority = 90;
    appConfig.GenericL2TxThreadCpu = 0;
    appConfig.GenericL2RxThreadCpu = 0;
    strncpy(appConfig.GenericL2Interface, "enp3s0", sizeof(appConfig.GenericL2Interface) - 1);
    memcpy((void *)appConfig.GenericL2Destination, defaultDestination, ETH_ALEN);

    /* Logging */
    appConfig.LogThreadPeriodNS = 500000000;
    appConfig.LogThreadPriority = 1;
    appConfig.LogThreadCpu = 7;
    appConfig.LogFile = strdup("reference.log");
    if (!appConfig.LogFile)
        goto out;
    appConfig.LogLevel = strdup(DefaultLogLevel);
    if (!appConfig.LogLevel)
        goto out;

    /* Debug */
    appConfig.DebugStopTraceOnRtt = false;
    appConfig.DebugStopTraceOnError = false;
    appConfig.DebugStopTraceRttLimitNS = 10000000;
    appConfig.DebugMonitorMode = false;
    memcpy((void *)appConfig.DebugMonitorDestination, defaultDebugMontitorDestination, ETH_ALEN);

    /* Stats */
    appConfig.StatsCollectionIntervalNS = 1e9;

    /* LogViaMQTT */
    appConfig.LogViaMQTT = false;
    appConfig.LogViaMQTTBrokerPort = 1883;
    appConfig.LogViaMQTTThreadPriority = 1;
    appConfig.LogViaMQTTThreadCpu = 7;
    appConfig.LogViaMQTTKeepAliveSecs = 60;
    appConfig.LogViaMQTTThreadPeriodNS = 1e9;
    appConfig.LogViaMQTTBrokerIP = strdup(DefaultLogViaMQTTBrokerIP);
    if (!appConfig.LogViaMQTTBrokerIP)
        goto out;

    appConfig.LogViaMQTTMeasurementName = strdup(DefaultLogViaMQTTMeasurementName);
    if (!appConfig.LogViaMQTTMeasurementName)
        goto out;
    return 0;
out:
    ConfigFree();
    return ret;
}

static bool ConfigCheckKeys(const char *trafficClass, enum SecurityMode mode, enum SecurityAlgorithm algorithm,
                            size_t keyLen, size_t ivPrefixLen)
{
    const size_t expectedKeyLen = algorithm == SECURITY_ALGORITHM_AES128_GCM ? 16 : 32;

    if (mode == SECURITY_MODE_NONE)
        return true;

    if (ivPrefixLen != SECURITY_IV_PREFIX_LEN)
    {
        fprintf(stderr, "%s IV prefix length should be %d!\n", trafficClass, SECURITY_IV_PREFIX_LEN);
        return false;
    }

    if (expectedKeyLen != keyLen)
    {
        fprintf(stderr, "%s key length mismatch!. Have %zu expected %zu for %s!\n", trafficClass, keyLen,
                expectedKeyLen, SecurityAlgorithmToString(algorithm));
        return false;
    }

    return true;
}

bool ConfigSanityCheck()
{
    const size_t minProfinetFrameSize = sizeof(struct VLANEthernetHeader) + sizeof(struct ProfinetRtHeader);
    const size_t minSecureProfinetFrameSize =
        sizeof(struct VLANEthernetHeader) + sizeof(struct ProfinetSecureHeader) + sizeof(struct SecurityChecksum);
    size_t minFrameSize;

    /*
     * Perform configuration sanity checks. This includes:
     *   - Traffic classes
     *   - Frame lengths
     *   - Limitations
     */

    /* Either GenericL2 or PROFINET should be active. */
    if (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(GenericL2) &&
        (CONFIG_IS_TRAFFIC_CLASS_ACTIVE(TsnHigh) || CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Rtc) ||
         CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Rta) || CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Dcp) ||
         CONFIG_IS_TRAFFIC_CLASS_ACTIVE(Lldp) || CONFIG_IS_TRAFFIC_CLASS_ACTIVE(UdpHigh) ||
         CONFIG_IS_TRAFFIC_CLASS_ACTIVE(UdpLow)))
    {
        fprintf(stderr, "Either use PROFINET or GenericL2!\n");
        fprintf(stderr, "For simulation of PROFINET and other middlewares in parallel "
                        "start multiple instances of ref&mirror application(s) with different profiles!\n");
        return false;
    }

    /* Frame lengths */
    if (appConfig.GenericL2FrameLength > GENL2_TX_FRAME_LENGTH ||
        appConfig.GenericL2FrameLength < (sizeof(struct VLANEthernetHeader) + sizeof(struct GenericL2Header) +
                                          appConfig.GenericL2PayloadPatternLength))
    {
        fprintf(stderr, "GenericL2FrameLength is invalid!\n");
        return false;
    }

    minFrameSize =
        appConfig.TsnHighSecurityMode == SECURITY_MODE_NONE ? minProfinetFrameSize : minSecureProfinetFrameSize;
    if (appConfig.TsnHighFrameLength > TSN_TX_FRAME_LENGTH ||
        appConfig.TsnHighFrameLength < (minFrameSize + appConfig.TsnHighPayloadPatternLength))
    {
        fprintf(stderr, "TsnHighFrameLength is invalid!\n");
        return false;
    }

    minFrameSize =
        appConfig.TsnLowSecurityMode == SECURITY_MODE_NONE ? minProfinetFrameSize : minSecureProfinetFrameSize;
    if (appConfig.TsnLowFrameLength > TSN_TX_FRAME_LENGTH ||
        appConfig.TsnLowFrameLength < (minFrameSize + appConfig.TsnLowPayloadPatternLength))
    {
        fprintf(stderr, "TsnLowFrameLength is invalid!\n");
        return false;
    }

    minFrameSize = appConfig.RtcSecurityMode == SECURITY_MODE_NONE ? minProfinetFrameSize : minSecureProfinetFrameSize;
    if (appConfig.RtcFrameLength > RTC_TX_FRAME_LENGTH ||
        appConfig.RtcFrameLength < (minFrameSize + appConfig.RtcPayloadPatternLength))
    {
        fprintf(stderr, "RtcFrameLength is invalid!\n");
        return false;
    }

    minFrameSize = appConfig.RtaSecurityMode == SECURITY_MODE_NONE ? minProfinetFrameSize : minSecureProfinetFrameSize;
    if (appConfig.RtaFrameLength > RTA_TX_FRAME_LENGTH ||
        appConfig.RtaFrameLength < (minFrameSize + appConfig.RtaPayloadPatternLength))
    {
        fprintf(stderr, "RtaFrameLength is invalid!\n");
        return false;
    }

    if (appConfig.DcpFrameLength > DCP_TX_FRAME_LENGTH ||
        appConfig.DcpFrameLength < (minProfinetFrameSize + appConfig.DcpPayloadPatternLength))
    {
        fprintf(stderr, "DcpFrameLength is invalid!\n");
        return false;
    }

    if (appConfig.LldpFrameLength > LLDP_TX_FRAME_LENGTH ||
        appConfig.LldpFrameLength <
            (sizeof(struct ethhdr) + sizeof(struct ReferenceMetaData) + appConfig.LldpPayloadPatternLength))
    {
        fprintf(stderr, "LldpFrameLength is invalid!\n");
        return false;
    }

    if (appConfig.UdpHighFrameLength > UDP_TX_FRAME_LENGTH ||
        appConfig.UdpHighFrameLength < (sizeof(struct ReferenceMetaData) + appConfig.UdpHighPayloadPatternLength))
    {
        fprintf(stderr, "UdpHighFrameLength is invalid!\n");
        return false;
    }

    if (appConfig.UdpLowFrameLength > UDP_TX_FRAME_LENGTH ||
        appConfig.UdpLowFrameLength < (sizeof(struct ReferenceMetaData) + appConfig.UdpLowPayloadPatternLength))
    {
        fprintf(stderr, "UdpLowFrameLength is invalid!\n");
        return false;
    }

    /* XDP and TxLauchTime combined doesn't work */
    if ((appConfig.GenericL2TxTimeEnabled && appConfig.GenericL2XdpEnabled) ||
        (appConfig.TsnHighTxTimeEnabled && appConfig.TsnHighXdpEnabled) ||
        (appConfig.TsnLowTxTimeEnabled && appConfig.TsnLowXdpEnabled))
    {
        fprintf(stderr, "TxTime and Xdp cannot be used at the same time!\n");
        return false;
    }

    /* XDP busy polling only works beginning with Linux kernel version v5.11 */
    if (!ConfigHaveBusyPoll() &&
        (appConfig.TsnHighXdpBusyPollMode || appConfig.TsnLowXdpBusyPollMode || appConfig.RtcXdpBusyPollMode ||
         appConfig.RtaXdpBusyPollMode || appConfig.GenericL2XdpBusyPollMode))
    {
        fprintf(stderr, "XDP busy polling selected, but not supported!\n");
        return false;
    }

    /* Check keys and IV */
    if (!ConfigCheckKeys("TsnHigh", appConfig.TsnHighSecurityMode, appConfig.TsnHighSecurityAlgorithm,
                         appConfig.TsnHighSecurityKeyLength, appConfig.TsnHighSecurityIvPrefixLength))
        return false;
    if (!ConfigCheckKeys("TsnLow", appConfig.TsnLowSecurityMode, appConfig.TsnLowSecurityAlgorithm,
                         appConfig.TsnLowSecurityKeyLength, appConfig.TsnLowSecurityIvPrefixLength))
        return false;
    if (!ConfigCheckKeys("Rtc", appConfig.RtcSecurityMode, appConfig.RtcSecurityAlgorithm,
                         appConfig.RtcSecurityKeyLength, appConfig.RtcSecurityIvPrefixLength))
        return false;
    if (!ConfigCheckKeys("Rta", appConfig.RtaSecurityMode, appConfig.RtaSecurityAlgorithm,
                         appConfig.RtaSecurityKeyLength, appConfig.RtaSecurityIvPrefixLength))
        return false;

    return true;
}

void ConfigFree(void)
{
    if (appConfig.ApplicationXdpProgram)
        free(appConfig.ApplicationXdpProgram);

    if (appConfig.TsnHighPayloadPattern)
        free(appConfig.TsnHighPayloadPattern);
    if (appConfig.TsnHighSecurityKey)
        free(appConfig.TsnHighSecurityKey);
    if (appConfig.TsnHighSecurityIvPrefix)
        free(appConfig.TsnHighSecurityIvPrefix);

    if (appConfig.TsnLowPayloadPattern)
        free(appConfig.TsnLowPayloadPattern);
    if (appConfig.TsnLowSecurityKey)
        free(appConfig.TsnLowSecurityKey);
    if (appConfig.TsnLowSecurityIvPrefix)
        free(appConfig.TsnLowSecurityIvPrefix);

    if (appConfig.RtcPayloadPattern)
        free(appConfig.RtcPayloadPattern);
    if (appConfig.RtcSecurityKey)
        free(appConfig.RtcSecurityKey);
    if (appConfig.RtcSecurityIvPrefix)
        free(appConfig.RtcSecurityIvPrefix);

    if (appConfig.RtaPayloadPattern)
        free(appConfig.RtaPayloadPattern);
    if (appConfig.RtaSecurityKey)
        free(appConfig.RtaSecurityKey);
    if (appConfig.RtaSecurityIvPrefix)
        free(appConfig.RtaSecurityIvPrefix);

    if (appConfig.DcpPayloadPattern)
        free(appConfig.DcpPayloadPattern);

    if (appConfig.LldpPayloadPattern)
        free(appConfig.LldpPayloadPattern);

    if (appConfig.UdpHighPayloadPattern)
        free(appConfig.UdpHighPayloadPattern);
    if (appConfig.UdpHighPort)
        free(appConfig.UdpHighPort);
    if (appConfig.UdpHighDestination)
        free(appConfig.UdpHighDestination);
    if (appConfig.UdpHighSource)
        free(appConfig.UdpHighSource);

    if (appConfig.UdpLowPayloadPattern)
        free(appConfig.UdpLowPayloadPattern);
    if (appConfig.UdpLowPort)
        free(appConfig.UdpLowPort);
    if (appConfig.UdpLowDestination)
        free(appConfig.UdpLowDestination);
    if (appConfig.UdpLowSource)
        free(appConfig.UdpLowSource);

    if (appConfig.GenericL2Name)
        free(appConfig.GenericL2Name);
    if (appConfig.GenericL2PayloadPattern)
        free(appConfig.GenericL2PayloadPattern);

    if (appConfig.LogFile)
        free(appConfig.LogFile);
    if (appConfig.LogLevel)
        free(appConfig.LogLevel);

    if (appConfig.LogViaMQTTBrokerIP)
        free(appConfig.LogViaMQTTBrokerIP);
    if (appConfig.LogViaMQTTMeasurementName)
        free(appConfig.LogViaMQTTMeasurementName);
}
