#!/bin/bash
#
# Copyright (C) 2022 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#

set -e

cd "$(dirname "$0")"

# Start PTP
../../../scripts/ptp.sh enp0s29f2
sleep 10

# Configure flow
./flow_ehl.sh enp0s29f2
sleep 10

# Start four instances of reference applications
cp ../../../build/xdp_kern_*.o .
../../../build/reference -c reference_vid100_ehl.yaml       > ref1.log &
sleep 1
../../../build/reference -c reference_opcua_vid200_ehl.yaml > ref2.log &
sleep 1
../../../build/reference -c reference_opcua_vid300_ehl.yaml > ref3.log &
sleep 1
../../../build/reference -c reference_avtp_vid400_ehl.yaml  > ref4.log &

exit 0
