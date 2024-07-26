.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2022-2024 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation build file.
..

Build
=====

The buildsystem is cmake. The applications can be build and installed by:

.. code:: bash

   mkdir build_x86
   cd build_x86
   cmake -DCMAKE_BUILD_TYPE=Release ..
   make -j`nproc`
   sudo make install

Setting the build type is important, as it defines the used compiler
flags. ``Release`` builds the application with optimizations and without debug
symbols. Other build types include: ``Debug`` or ``RelWithDebInfo``.

The applications have the following dependencies:

- Run time: libbpf, libyaml, libxdp, libssl
- Build time: cmake, gcc, clang, llvm, pkg-config
- Utilities: linuxptp, ethtool, iproute2, rt-tests, iperf3

For Debian based systems do:

.. code:: bash

   apt update
   apt install -y build-essential clang llvm cmake pkg-config \
      libbpf-dev libyaml-dev libc6-dev rt-tests ethtool iproute2 \
      iperf3 linuxptp libxdp-dev libssl-dev

.. Note:: For Debian Bullseye ``libxdp`` is packaged in backports.

Furthermore, the Linux TSN ``Testbench`` requires Linux kernel version >= v5.12.
PREEMPT_RT is recommended. In addition, the following configuration options have
to be set:

- CONFIG_PTP_1588_CLOCK
- CONFIG_BPF
- CONFIG_BPF_SYSCALL
- CONFIG_DEBUG_INFO
- CONFIG_DEBUG_INFO_BTF
- CONFIG_XDP_SOCKETS
- CONFIG_NET_SCH_MQPRIO
- CONFIG_NET_SCH_TAPRIO
- CONFIG_NET_SCH_ETF
- CONFIG_NET_SCH_INGRESS
- CONFIG_NET_CLS_*

Additional Options
^^^^^^^^^^^^^^^^^^

Some features are added by using additional CMake opitions, the table bellow presents those features and options.

.. list-table:: Features & CMake options
   :widths: 50 50
   :header-rows: 1

   * - Feature
     - Option

   * - MQTT
     - WITH_MQTT
