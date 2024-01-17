#!/bin/bash
#
# Copyright (C) 2023 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#

set -e

cd "$(dirname "$0")"

# Configure flow
./flow.sh
sleep 30

# Start one instance of mirror application
cp ../../build/xdp_kern_*.o .
../../build/mirror -c mirror_vid100.yaml > mirror1.log &

exit 0
