#!/bin/bash
#
# Copyright (C) 2022 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for Intel i210.
#

set -e

#
# Command line arguments.
#
INTERFACE=$1

[ -z $INTERFACE ] && INTERFACE="enp2s0" # default: enp2s0

#
# Enable NAPI threaded mode: This allows the NAPI processing being executed in
# dedicated kernel threads instead of using NET_RX soft irq. Using these allows
# to prioritize the Rx processing in accordance to use case.
#
echo 1 > /sys/class/net/${INTERFACE}/threaded

#
# Disable Rx VLAN offload. Each PN middleware uses a dedicated VLAN. The eBPF
# programs checks for it to dispatch frames to the correct application.
#
ethtool -K ${INTERFACE} rx-vlan-offload off

#
# Increase number of queues.
#
ethtool -L ${INTERFACE} combined 4

#
# Increase Tx and Rx ring sizes.
#
ethtool -G ${INTERFACE} rx 4096 tx 4096

#
# Tx Assignment.
#
# PCP 6 - Queue 0 - TSN High
# PCP 5 - Queue 1 - TSN Low
# PCP 4 - Queue 2 - RTC
# PCP 3/2/1/7 - Queue 3 - RTA / LLDP / DCP / PTP / UDP
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root mqprio num_tc 4 \
   map 3 3 3 3 3 2 1 0 3 3 3 3 3 3 3 3 \
   queues 1@0 1@1 1@2 1@3 \
   hw 0

#
# Rx Queues Assignment.
#
# Rx Q 3 - All Traffic
# Rx Q 2 - RTC
# Rx Q 1 - TSN Low
# Rx Q 0 - TSN High
#
ethtool -K ${INTERFACE} ntuple on

#
# NOTE: Match Rx traffic class by PCP field of VLAN tagged frames. For Profinet
# TSN all traffic is categorized by its own PCP values. This method works for
# Intel i210 and i225.
#

# TSN High: PCP 6 -> Queue 0
ethtool -N ${INTERFACE} flow-type ether vlan 0xc000 m 0x1fff action 0

# TSN Low: PCP 5 -> Queue 1
ethtool -N ${INTERFACE} flow-type ether vlan 0xa000 m 0x1fff action 1

# RTC: PCP 4 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0x8000 m 0x1fff action 2

# RTA: PCP 3 -> Queue 3
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
# Increase NAPI thread priorities. By default, every NAPI thread uses
# SCHED_OTHER.
#
# RT NAPI Threads: CPU 0 and FIFO 85
# NON-RT NAPI Threads: CPU 1 and SCHED_OTHER
#
RT_NAPITHREADS=`ps aux | grep napi | grep ${INTERFACE} | awk '{ print $2; }' | head -n 3`
for task in ${RT_NAPITHREADS}; do
  chrt -p -f 85 $task
  taskset -p 01 $task
done

NON_RT_NAPITHREADS=`ps aux | grep napi | grep ${INTERFACE} | awk '{ print $2; }' | tail -n 1`
for task in ${NON_RT_NAPITHREADS}; do
  taskset -p 02 $task
done

exit 0
