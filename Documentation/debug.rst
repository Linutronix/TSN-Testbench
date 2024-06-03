.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2024 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation debug file.
..

Debug
=====

Debugging of real time outliers
-------------------------------

In case test runs indicate outliers or unusual round-trip times in the statistics, Linux ``ftrace``
can be used to find the root cause. This can be done like this:

.. code:: bash

   # Start tracing
   trace-cmd start -e sched -e syscalls -e irq

   # Set DebugStopTraceOnRtt to True and DebugStopTraceRttLimitNS to 2x cycle time in reference.yaml
   # configuration file

   # Start reference and mirror as usual

   # The reference application will stop after a round-trip time greater than
   # DebugStopTraceRttLimitNS is hit and will output an information message about it

   # Get the trace
   trace-cmd extract -a

   # Copy trace.dat to development machine

   # Analyze trace.dat with kernelshark or tracecompass to find the issue
