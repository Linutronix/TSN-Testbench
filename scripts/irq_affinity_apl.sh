#!/bin/bash
#
# Copyright (C) 2022 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup IRQ affinities.
#

set -e

#
# Command line arguments.
#
INTERFACE=$1
[ -z $INTERFACE ] && INTERFACE="enp2s0" # default: enp2s0

#
# Increase IRQ thread priorities. By default, every IRQ thread has priority 50.
#
# CPU 0: RT traffic classes
# CPU 1: Non-RT traffic classes
#
RT_IRQTHREADS=`ps aux | grep irq | grep ${INTERFACE} | awk '{ print $2; }' | head -n 3`
for task in ${RT_IRQTHREADS}; do
  chrt -p -f 85 $task
  taskset -p 01 $task
done

NON_RT_IRQTHREADS=`ps aux | grep irq | grep ${INTERFACE} | awk '{ print $2; }' | tail -n 2`
for task in ${NON_RT_IRQTHREADS}; do
  taskset -p 02 $task
done

exit 0
