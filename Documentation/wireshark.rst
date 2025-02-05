.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2024 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation Wireshark guide.
..

.. _Wireshark:

Wireshark
=========

Wireshark Dissector
^^^^^^^^^^^^^^^^^^^

The Linux RealTime Communication Testbench frame format is different from regular PROFINET
frames. It carries its own MetaData which is used for gathering statistics and catching
errors. Therefore, the default PROFINET dissector in Wireshark indicates erroneous data. To show
more useful data use the dissector provided in ``scripts/testbench.lua``.

Copy this file to the Wireshark plugin folder. The plugin folder can be determined by going to help
-> About Wireshark -> Folders. Afterwards restart Wireshark. It should look like this:

.. image:: images/wireshark_dissector.png
  :width: 600
  :alt: Wireshark dissector example
