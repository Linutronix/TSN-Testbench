#!/bin/bash
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2024 Intel Corporation
# Author Walfred Tedeschi <walfred.tedeschi@intel.com>
#

id=$(docker ps -aqf "name=grafana")
sudo docker exec -ti $id grafana cli admin reset-admin-password ${1}
