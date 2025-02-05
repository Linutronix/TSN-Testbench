#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2023-2024 Linutronix GmbH
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
RUN apt install -y iperf3 linuxptp libxdp-dev libssl-dev libmosquitto-dev
RUN apt install -y git

# Install RTC Testbench
WORKDIR /root
RUN git clone https://www.github.com/Linutronix/RTC-Testbench
RUN mkdir -p RTC-Testbench/build
WORKDIR /root/RTC-Testbench/build
RUN cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DWITH_MQTT=TRUE ..
RUN make -j`nproc`
RUN make install
