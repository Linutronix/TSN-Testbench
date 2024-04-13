.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2024 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation quick start guide.
..

.. _Quickstart:

Quick Start Guide
=================

Introduction
^^^^^^^^^^^^

The following sections provide an overview how to quickly setup the Linux TSN Testbench. It includes
suited and available hardware as well as the recommended Linux system.

Hardware
^^^^^^^^

The Linux TSN Testbench runs well on x86 processors with Intel i225/i226 TSN NIC(s). These network
cards include capabilities such time synchronization via PTP, 802.1Qav, 802.1Qbv, Tx Launch Time and
multi queue. Furthermore, the NIC(s) are connected via PCIe and can be used in any system with
corresponding PCIe slots.

Example industrial PCs are:

- https://up-shop.org/default/up-squared-pro-7000-edge-series.html
- https://www.kontron.com/en/products/kbox-c-104-tgl/p173851

Two machines are required at minimum. One to run the ``reference`` application and one to execute
the ``mirror``. Network switches can be used as well. However, the switches should support 802.1AS
for the time synchronization via PTP.

Linux
^^^^^

The recommend Linux distribution is Debian Stable (Bookworm). It includes all necessary libraries
and tools to run the Linux TSN Testbench. Debian can be installed on any PC by using the Debian
installer:

- https://www.debian.org/distrib/

Once Debian is and up and running the Linux TSN Testbench and its dependencies can be installed:

.. code:: bash

   # Install dependencies
   apt update
   apt install -y build-essential clang llvm cmake pkg-config \
      libbpf-dev libyaml-dev libc6-dev rt-tests ethtool iproute2 \
      iperf3 linuxptp libxdp-dev libssl-dev libmosquitto-dev git

   # Install Linux TSN Testbench
   git clone https://www.github.com/Linutronix/TSN-Testbench
   mkdir -p TSN-Testbench/build
   cd TSN-Testbench/build
   cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DWITH_MQTT=TRUE ..
   make -j`nproc`
   make install

The applications require a Linux real time kernel with PREEMPT_RT. On Debian the kernel can be
simply installed via the package management:

.. code:: bash

   # Install real time Linux kernel
   apt update
   apt install -y linux-image-rt-amd64

Configuration
^^^^^^^^^^^^^

In addition, the Linux TSN Testbench requires a configuration. That is used to specify what and how
many frames are transmitted and received. Furthermore, it specifies system parameters such as what
priorities, queues and CPU(s) are used. Example configurations are provided, but have to be adjusted
to the particular systems. At least, the names of the network interfaces and the MAC/IP addresses
have to be changed.

Starting point for PROFINET TSN:

- https://github.com/Linutronix/TSN-Testbench/tree/main/tests/profinet

Starting point for OPC/UA:

- https://github.com/Linutronix/TSN-Testbench/tree/main/tests/opcua

As soon as the configuration files are created, the ``reference`` and ``mirror`` application can be
started on two different nodes in the network. The ``reference`` logs the statistics for
analysis. For a graphical visualization with Grafana, see:
https://linutronix.github.io/TSN-Testbench/mqtt.html
