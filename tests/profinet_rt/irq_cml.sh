#!/bin/bash
#
# Copyright (C) 2023 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup IRQ affinities and prios.
#

set -e

#
# Command line arguments.
#
INTERFACE=$1
[ -z $INTERFACE ] && INTERFACE="enp3s0" # default: enp3s0

#
# Increase IRQ thread priorities. By default, every IRQ thread has priority 50.
#
RT_IRQTHREADS=$(ps aux | grep irq | grep ${INTERFACE} | awk '{ print $2; }')
for task in ${RT_IRQTHREADS}; do
  chrt -p -f 85 $task
done

exit 0
