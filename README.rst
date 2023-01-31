ghidra-fidb-dos-win16-pipeline
==============================

Scripts for scraping vintage x86 C/C++ libraries in Ghidra, in order to generate FunctionId databases.

Based on the scripts from https://github.com/threatrack/ghidra-fid-generator.

Supported libraries:

- blc200 - Borland C++ 2.0
- blc300 - Borland C++ 3.0
- blc310 - Borland C++ 3.1
- msc400 - Microsoft C Compiler 4.0
- msc500 - Microsoft C Compiler 5.0
- msc510 - Microsoft C Compiler 5.1
- msc600 - Microsoft C Compiler 6.0
- msc700 - Microsoft C/C++ 7.0
- msvc152c - Microsoft Visual C++ 1.52c


How to find what C library you need
-----------------------------------

Start with the EXE of the program you want to disassemble.

Make sure the executable isn't packed. Back in the day everything had to fit on a floppy disk, so it was popular to ship packed EXEs: a tiny decompressor code stub plus a compressed blob. It's best to sort this out now, as Ghidra won't be able to open packed executables. For DOS your best bet would be to use Ben Castricum's UNP tool, as it supports most common packer formats - https://bencastricum.nl/unp/

Run the command-line ``strings`` utility over the EXE file. Ideally you are looking for copyright strings for the compiler, e.g.:

.. code-block:: none

    Borland C++ - Copyright 1991 Borland Intl.

In this case, the year pegs the executable as being compiled with Borland C++ 2.0.

If there are no copyright strings, the next thing to look for are error messages related to system calls; i.e. ones not written by the developer, but that were bundled as part of the C library. Here's a block of them from the same EXE:

.. code-block:: none
   
    Error 0
    Invalid function number
    No such file or directory
    Path not found
    Too many open files
    Permission denied
    Bad file number
    Memory arena trashed
    Not enough memory

Plug the exact wordings of the more unique error messages into a search engine. I've had great results with GitHub code search, as there's lots of old compiler source code people have uploaded. After a bit of sleuthing you should be able to narrow down which compiler family was used, and from there it's a case of finding the version that was available before the release date of your target EXE.

How to process old C libraries
------------------------------

Find a copy of the old compiler. I have been using the archive at https://winworldpc.com/library/dev, a very comprehensive collection of early DOS/Win16 compiler versions.

Using an emulator such as DOSBox, mount the disk image(s) and install the compiler to an empty root folder. Be sure to include all of the optional features, such as support for different memory modes.


Set the following environment variables (if required):

- GHIDRA_HOME: Base location for the Ghidra install. Defaults to /opt/ghidra
- GHIDRA_HEADLESS: Location of the "analyzeHeadless" script in the Ghidra install. Defaults to $GHIDRA_HOME/support/analyzeHeadless
- GHIDRA_SCRIPTS: Location of the FunctionID scripts in the Ghidra install. Defaults to $GHIDRA_HOME/Ghidra/Features/FunctionID/ghidra_scripts
- GHIDRA_PROJ: Location to create the Ghidra project used for processing. Defaults to /tmp/ghidra-proj

For processing, you will need several gigabytes of space for the Ghidra project; approx 1GB of space for every 1MB of library data. 

Finally, run ./fidb-rip.py; this will execute all of the steps required to produce a FIDB file.
