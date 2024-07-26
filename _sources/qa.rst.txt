.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2022 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation qa file.
..

Quality Assurance
=================

License Checks
--------------

The license for the Linux TSN ``Testbench`` is the permissive BSD-2-Clause. All
files have a valid SPDX identifier (see https://spdx.dev/). The provided license
information can be automatically checked for errors by using the ``spdxcheck``
tool from the Linux kernel project. Example:

.. code:: bash

   % ~/git/linux/scripts/spdxcheck.py -v

   License files:                2
   Exception files:              0
   License IDs                   5
   Exception IDs                 0

   Files excluded:               5
   Files checked:              102
   Lines checked:              358
   Files with SPDX:             94  92%
   Files with errors:            0

   Directories accounted:       12
   Directories complete:         7  58%

No errors should be printed.

Coding Style Check
------------------

The coding style for the Linux TSN ``Testbench`` is the Linux kernel style. The
rules are described here:

- https://www.kernel.org/doc/html/latest/process/coding-style.html#codingstyle

The coding style can be enforced automatically by using ``clang-format`` (see
https://clang.llvm.org/docs/ClangFormat.html). Example:

.. code:: bash

   % clang-format -i src/*.c src/*.h

This corrects errors in place for all C source files.

Furthermore, the naming of variables, structs and function can be checked (and
fixed inplace) by running ``clang-tidy``:

.. code:: bash

   % mkdir build
   % cd build
   % cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
   % make -j`nproc`
   % run-clang-tidy
