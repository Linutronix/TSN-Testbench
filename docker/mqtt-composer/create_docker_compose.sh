# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2024 Intel Corporation
# Author Walfred Tedeschi <walfred.tedeschi@intel.com>
#
#!/bin/bash

git clone https://github.com/Miceuz/docker-compose-mosquitto-influxdb-telegraf-grafana
pushd ./docker-compose-mosquitto-influxdb-telegraf-grafana
git checkout 1f873f2
cp ../docker_composer.diff .
patch docker-compose.yml < docker_composer.diff
mv docker-compose.yml ../.
popd
rm -rf docker-compose-mosquitto-influxdb-telegraf-grafana
