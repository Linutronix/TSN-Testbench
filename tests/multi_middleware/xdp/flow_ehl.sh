#!/bin/bash
#
# Copyright (C) 2021 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Rx and Tx traffic flows on Intel Elkhart Lake.
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

[ -z $INTERFACE ]    && INTERFACE="eno1"       # default: eno1
[ -z $CYCLETIME_NS ] && CYCLETIME_NS="1000000" # default: 1ms
[ -z $BASETIME ]     && BASETIME=`date '+%s000000000' -d '60 sec'` # default: now + 60s

# Load needed kernel modules
modprobe sch_taprio || true

#
# Enable NAPI threaded mode: This allows the NAPI processing being executed in
# dedicated kernel threads instead of using NET_RX soft irq. Using these allows
# to prioritize the Rx processing in accordance to use case.
#
echo 1 > /sys/class/net/${INTERFACE}/threaded

#
# Configure the interface: Tailor IRQ settings towards lower cycle times,
# e.g. 500us.
#
ethtool --per-queue ${INTERFACE} queue_mask 0xff --coalesce tx-usecs 500 tx-frames 16

#
# Disable VLAN Rx offload.
#
ethtool -K ${INTERFACE} rx-vlan-offload off

#
# Qbv configuration.
#
ENTRY1_NS=`echo "$CYCLETIME_NS * 12.5 / 100" | bc` # TSN High
ENTRY2_NS=`echo "$CYCLETIME_NS * 12.5 / 100" | bc` # TSN Low
ENTRY3_NS=`echo "$CYCLETIME_NS * 12.5 / 100" | bc` # RT
ENTRY4_NS=`echo "$CYCLETIME_NS * 12.5 / 100" | bc` # RT
ENTRY5_NS=`echo "$CYCLETIME_NS * 50 / 100" | bc`   # Non-RT

#
# Tx Assignment with Qbv and full hardware offload.
#
# PCP 0 - Queue 0 - UDP Low
# PCP 1 - Queue 1 - UDP High
# PCP 2 - Queue 2 - DCP
# PCP 3 - Queue 3 - RTA
# PCP 4 - Queue 5 - RTC
# PCP 5 - Queue 6 - TSN LOW
# PCP 6 - Queue 7 - TSN HIGH
# PCP 7 - Queue 4 - PTP/LLDP
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root taprio num_tc 8 \
   map 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 \
   queues 1@0 1@1 1@2 1@3 1@4 1@5 1@6 1@7 \
   base-time ${BASETIME} \
   sched-entry S 0x80 ${ENTRY1_NS} \
   sched-entry S 0x40 ${ENTRY2_NS} \
   sched-entry S 0x20 ${ENTRY3_NS} \
   sched-entry S 0x10 ${ENTRY4_NS} \
   sched-entry S 0x0f ${ENTRY5_NS} \
   flags 0x02

#
# Create VLAN interfaces.
#
ip link add link ${INTERFACE} name ${INTERFACE}.100 type vlan id 100
ip link add link ${INTERFACE} name ${INTERFACE}.200 type vlan id 200
ip link add link ${INTERFACE} name ${INTERFACE}.300 type vlan id 300
ip link add link ${INTERFACE} name ${INTERFACE}.400 type vlan id 400

ip link set ${INTERFACE}.100 up
ip link set ${INTERFACE}.200 up
ip link set ${INTERFACE}.300 up
ip link set ${INTERFACE}.400 up

#
# Rx Assignment.
#
# PCP 0 - Queue 0 - UDP Low
# PCP 1 - Queue 1 - UDP High
# PCP 2 - Queue 2 - DCP
# PCP 3 - Queue 3 - RTA
# PCP 4 - Queue 5 - RTC
# PCP 5 - Queue 6 - TSN LOW
# PCP 6 - Queue 7 - TSN HIGH
# PCP 7 - Queue 4 - PTP/LLDP
#
tc qdisc add dev ${INTERFACE} ingress
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 0 hw_tc 0
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 1 hw_tc 1
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 2 hw_tc 2
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 3 hw_tc 3
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 4 hw_tc 5
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 5 hw_tc 6
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 6 hw_tc 7
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 7 hw_tc 4

#
# PTP and LLDP are transmitted untagged. Steer them via EtherType.
#
tc filter add dev ${INTERFACE} parent ffff: protocol 0x88f7 flower hw_tc 4
tc filter add dev ${INTERFACE} parent ffff: protocol 0x88cc flower hw_tc 4

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
