#!/bin/bash
#
# Copyright (C) 2023 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for Intel i225 for netload scenario.
#

set -e

#
# Command line arguments.
#
INTERFACE=$1
CYCLETIME_NS=$2
BASETIME=$3

[ -z $INTERFACE ]    && INTERFACE="enp3s0"     # default: enp3s0
[ -z $CYCLETIME_NS ] && CYCLETIME_NS="1000000" # default: 1ms
[ -z $BASETIME ]     && BASETIME=`date '+%s000000000' -d '-30 sec'` # default: now - 30s

# Load needed kernel modules
modprobe sch_taprio || true

#
# Enable NAPI threaded mode: This allows the NAPI processing being executed in
# dedicated kernel threads instead of using NET_RX soft irq. Using these allows
# to prioritize the Rx processing in accordance to use case.
#
echo 1 > /sys/class/net/${INTERFACE}/threaded

#
# Reduce link speed.
#
ethtool -s ${INTERFACE} speed 1000 autoneg on duplex full

#
# Split traffic between TSN streams, priority and everything else.
#
ENTRY1_NS=`echo "$CYCLETIME_NS * 50 / 100" | bc` # RTC
ENTRY2_NS=`echo "$CYCLETIME_NS * 25 / 100" | bc` # TSN Streams / Prio
ENTRY3_NS=`echo "$CYCLETIME_NS * 25 / 100" | bc` # Everything else

#
# Tx Assignment with Qbv and full hardware offload.
#
# PCP 4   - Rx Q 0 - RTC
# PCP 6/5 - Rx Q 1 - TSN Streams / Prio
# PCP X   - Rx Q 2 - Everything else
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root taprio num_tc 3 \
   map 2 2 2 2 2 2 1 0 2 2 2 2 2 2 2 2 \
   queues 1@0 1@1 2@2 \
   base-time ${BASETIME} \
   sched-entry S 0x01 ${ENTRY1_NS} \
   sched-entry S 0x02 ${ENTRY2_NS} \
   sched-entry S 0x04 ${ENTRY3_NS} \
   flags 0x02

#
# Rx Queues Assignment.
#
# PCP 4   - Rx Q 0 - RTC
# PCP 6/5 - Rx Q 1 - TSN Streams / Prio
# PCP X   - Rx Q 2 - Everything else
#
ethtool -K ${INTERFACE} ntuple on

# RTC: PCP 4 -> Queue 0
ethtool -N ${INTERFACE} flow-type ether vlan 0x8000 m 0x1fff action 0

# TSN Streams: PCP 6 -> Queue 1
ethtool -N ${INTERFACE} flow-type ether vlan 0xc000 m 0x1fff action 1

# TSN Streams: PCP 5 -> Queue 1
ethtool -N ${INTERFACE} flow-type ether vlan 0xa000 m 0x1fff action 1

# PCP 3 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0x6000 m 0x1fff action 2

# PCP 2 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0x4000 m 0x1fff action 2

# PCP 7 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0xe000 m 0x1fff action 2

# PCP 1 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0x2000 m 0x1fff action 2

# PCP 0 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0x0000 m 0x1fff action 2

#
# PTP and LLDP are transmitted untagged. Steer them via EtherType.
#
ethtool -N ${INTERFACE} flow-type ether proto 0x88f7 action 1
ethtool -N ${INTERFACE} flow-type ether proto 0x88cc action 1

#
# Increase Tx and Rx ring sizes.
#
ethtool -G ${INTERFACE} rx 4096 tx 4096

#
# Increase IRQ thread priorities. By default, every IRQ thread has priority 50.
#
IRQTHREADS=`ps aux | grep irq | grep ${INTERFACE} | awk '{ print $2; }'`
for task in ${IRQTHREADS}; do
  chrt -p -f 85 $task
done

#
# Increase NAPI thread priorities. By default, every NAPI thread uses
# SCHED_OTHER.
#
NAPITHREADS=`ps aux | grep napi | grep ${INTERFACE} | awk '{ print $2; }'`
for task in ${NAPITHREADS}; do
  chrt -p -f 85 $task
done

exit 0
