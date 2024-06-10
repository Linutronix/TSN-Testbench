#!/bin/bash
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2024 Intel Corporation
# Author Walfred Tedeschi <walfred.tedeschi@intel.com>
#

git clone https://github.com/Miceuz/docker-compose-mosquitto-influxdb-telegraf-grafana
pushd ./docker-compose-mosquitto-influxdb-telegraf-grafana
git checkout 1f873f2
cp ../docker_composer.diff .
patch docker-compose.yml < docker_composer.diff
current_user_id=$(id -u)
sed  -i -e 's/user\:.*/user: "'${current_user_id}'"/g' docker-compose.yml
mv docker-compose.yml ../.
popd
rm -rf docker-compose-mosquitto-influxdb-telegraf-grafana
