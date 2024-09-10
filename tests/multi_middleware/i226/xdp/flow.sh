#!/bin/bash
#
# Copyright (C) 2021-2024 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Rx and Tx traffic flows for Intel i226.
#
# Rx steering is based on PCP values. Tx steering is based on socket priorities
# which are mapped to traffic classes and to timeslots accordingly.
#

set -e

#
# Command line arguments.
#
INTERFACE=$1
CYCLETIME_NS=$2
BASETIME=$3

[ -z $INTERFACE ] && INTERFACE="enp3s0"                          # default: enp3s0
[ -z $CYCLETIME_NS ] && CYCLETIME_NS="1000000"                   # default: 1ms
[ -z $BASETIME ] && BASETIME=$(date '+%s000000000' -d '-30 sec') # default: now - 30s

# Load needed kernel modules
modprobe sch_taprio || true

#
# Enable NAPI threaded mode: This allows the NAPI processing being executed in
# dedicated kernel threads instead of using NET_RX soft irq. Using these allows
# to prioritize the Rx processing in accordance to use case.
#
echo 1 >/sys/class/net/${INTERFACE}/threaded

#
# Reduce link speed.
#
ethtool -s ${INTERFACE} speed 1000 autoneg on duplex full

#
# Disable VLAN Rx offload.
#
ethtool -K ${INTERFACE} rx-vlan-offload off

#
# Qbv configuration.
#
ENTRY1_NS=$(echo "$CYCLETIME_NS * 12.5 / 100" | bc) # TSN High
ENTRY2_NS=$(echo "$CYCLETIME_NS * 12.5 / 100" | bc) # TSN Low
ENTRY3_NS=$(echo "$CYCLETIME_NS * 12.5 / 100" | bc) # RT
ENTRY4_NS=$(echo "$CYCLETIME_NS * 62.5 / 100" | bc) # RT / Non-RT

#
# Tx Assignment with Qbv and full hardware offload.
#
# PCP 6 - Queue 0 - TSN High
# PCP 5 - Queue 1 - OPC/UA #1
# PCP 4 - Queue 2 - OPC/UA #2
# PCP 3 - Queue 3 - AVTP / All other traffic
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root taprio num_tc 4 \
  map 3 3 3 3 3 2 1 0 3 3 3 3 3 3 3 3 \
  queues 1@0 1@1 1@2 1@3 \
  base-time ${BASETIME} \
  sched-entry S 0x01 ${ENTRY1_NS} \
  sched-entry S 0x02 ${ENTRY2_NS} \
  sched-entry S 0x04 ${ENTRY3_NS} \
  sched-entry S 0xf8 ${ENTRY4_NS} \
  flags 0x02

#
# Rx Queues Assignment.
#
# Rx Q 3 - AVTP / All other traffic
# Rx Q 2 - OPC/UA #2
# Rx Q 1 - OPC/UA #1
# Rx Q 0 - TSN High
#
ethtool -K ${INTERFACE} ntuple on

# TSN High: PCP 6 -> Queue 0
ethtool -N ${INTERFACE} flow-type ether vlan 0xc000 m 0x1fff action 0

# OPC/UA #1: PCP 5 -> Queue 1
ethtool -N ${INTERFACE} flow-type ether vlan 0xa000 m 0x1fff action 1

# OPC/UA #2: PCP 4 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0x8000 m 0x1fff action 2

# AVTP: PCP 3 -> Queue 3
ethtool -N ${INTERFACE} flow-type ether vlan 0x6000 m 0x1fff action 3

# DCP: PCP 2 -> Queue 3
ethtool -N ${INTERFACE} flow-type ether vlan 0x4000 m 0x1fff action 3

# LLDP/PTP: PCP 7 -> Queue 3
ethtool -N ${INTERFACE} flow-type ether vlan 0xe000 m 0x1fff action 3

# UDP Low: PCP 1 -> Queue 3
ethtool -N ${INTERFACE} flow-type ether vlan 0x2000 m 0x1fff action 3

# UDP High: PCP 0 -> Queue 3
ethtool -N ${INTERFACE} flow-type ether vlan 0x0000 m 0x1fff action 3

#
# PTP and LLDP are transmitted untagged. Steer them via EtherType.
#
ethtool -N ${INTERFACE} flow-type ether proto 0x88f7 action 3
ethtool -N ${INTERFACE} flow-type ether proto 0x88cc action 3

#
# Increase Tx and Rx ring sizes.
#
ethtool -G ${INTERFACE} rx 4096 tx 4096

#
# Increase IRQ thread priorities. By default, every IRQ thread has priority 50.
#
IRQTHREADS=$(ps aux | grep irq | grep ${INTERFACE} | awk '{ print $2; }')
for task in ${IRQTHREADS}; do
  chrt -p -f 85 $task
done

#
# Increase NAPI thread priorities. By default, every NAPI thread uses
# SCHED_OTHER.
#
NAPITHREADS=$(ps aux | grep napi | grep ${INTERFACE} | awk '{ print $2; }')
for task in ${NAPITHREADS}; do
  chrt -p -f 85 $task
done

exit 0
