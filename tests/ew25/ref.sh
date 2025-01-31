#!/bin/bash
#
# Copyright (C) 2023-2025 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#

set -e

cd "$(dirname "$0")"

# Start PTP
../../scripts/ptp.sh enp88s0
sleep 30

# Configure flow
./flow.sh enp88s0
sleep 30

# Start one instance of reference application
cp ../../build/xdp_kern_*.o .
../../build/reference -c reference_vid100.yaml

exit 0
