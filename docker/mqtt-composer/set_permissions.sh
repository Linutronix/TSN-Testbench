#!/bin/bash
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2024 Intel Corporation
# Author Walfred Tedeschi <walfred.tedeschi@intel.com>
#

sudo usermod -aG docker $USER
chgrp docker grafana-data influxdb-storage
chmod 774 -R influxdb-storage grafana-data

