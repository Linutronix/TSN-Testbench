#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2023 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
FROM debian:bookworm

ENV DEBIAN_FRONTEND noninteractive

# Update
RUN apt update
RUN apt upgrade -y

# Lang
RUN apt install -y locales
RUN echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && locale-gen
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

# Install essentials
RUN apt install -y build-essential clang llvm cmake pkg-config
RUN apt install -y libbpf-dev libyaml-dev libc6-dev rt-tests ethtool iproute2
RUN apt install -y iperf3 linuxptp libxdp-dev libssl-dev

# Install TSN Testbench
COPY tsn-testbench_4.0-1_amd64.deb /tmp
RUN dpkg -i /tmp/tsn-testbench_4.0-1_amd64.deb
RUN apt --fix-broken install
