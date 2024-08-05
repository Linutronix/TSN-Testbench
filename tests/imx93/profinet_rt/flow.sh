#!/bin/bash
#
# Copyright (C) 2024 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for imx93 stmmac for PROFINET RT scenario.
#

set -e

#
# Command line arguments.
#
INTERFACE=$1

[ -z $INTERFACE ] && INTERFACE="eth1"
BASETIME=$(date '+%s000000000' -d '60 sec')

# Load needed kernel modules
modprobe sch_taprio || true

#
# Configure napi_defer_hard_irqs and gro_flush_timeout for busy polling:
#  - napi_defer_hard_irqs: How often will the NAPI processing be defered?
#  - gro_flush_timeout: Timeout when the kernel will take over NAPI processing.
#    Has to be greather than the $CYCLETIME_NS
#
GRO_FLUSH_TIMEOUT="2000000"
echo 10 >/sys/class/net/${INTERFACE}/napi_defer_hard_irqs
echo ${GRO_FLUSH_TIMEOUT} >/sys/class/net/${INTERFACE}/gro_flush_timeout

#
# Disable VLAN Rx offload.
#
ethtool -K ${INTERFACE} rx-vlan-offload off

#
# Tx Assignment with Qbv and full hardware offload: 20% RT, 80% non-RT.
#
# Tx Q 0 - Everything else
# Tx Q 1 - RTC
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root taprio num_tc 2 \
  map 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 \
  queues 1@0 1@1 \
  base-time ${BASETIME} \
  sched-entry S 0x02 200000 \
  sched-entry S 0x01 800000 \
  flags 0x02

#
# Rx Queues Assignment.
#
# Rx Q 0 - Everything else
# Rx Q 1 - RTC
#
tc qdisc add dev ${INTERFACE} ingress
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 0 hw_tc 0
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 1 hw_tc 0
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 2 hw_tc 0
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 3 hw_tc 0
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 4 hw_tc 1
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 5 hw_tc 0
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 6 hw_tc 0
tc filter add dev ${INTERFACE} parent ffff: protocol 802.1Q flower vlan_prio 7 hw_tc 0

#
# PTP and LLDP are transmitted untagged. Steer them via EtherType.
#
tc filter add dev ${INTERFACE} parent ffff: protocol 0x88f7 flower hw_tc 0
tc filter add dev ${INTERFACE} parent ffff: protocol 0x88cc flower hw_tc 0

#
# Increase IRQ thread priorities. By default, every IRQ thread has priority 50.
#
IRQTHREADS=$(ps aux | grep irq | grep ${INTERFACE} | awk '{ print $2; }')
for task in ${IRQTHREADS}; do
  chrt -p -f 85 $task
done

exit 0
