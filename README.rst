ghidra-fidb-dos-win16
=====================

Scripts for scraping vintage x86 C/C++ libraries in Ghidra, in order to generate FunctionID databases.

Based on the scripts from https://github.com/threatrack/ghidra-fid-generator.

Supported libraries:

- blc200 - Borland C++ 2.0 (1990)
- blc300 - Borland C++ 3.0 (1991)
- blc310 - Borland C++ 3.1 (1992)
- mfc250 - Microsoft Foundation Classes 2.5 (1995)
- msc300 - Microsoft C Compiler 3.0 (1985)
- msc400 - Microsoft C Compiler 4.0 (1986)
- msc500 - Microsoft C Compiler 5.0 (1987)
- msc510 - Microsoft C Compiler 5.1 (1988)
- msc600 - Microsoft C Compiler 6.0 (1991)
- msc700 - Microsoft C/C++ 7.0 (1992)
- msvc152c - Microsoft Visual C++ 1.52c (1995)

How to add FunctionID databases to Ghidra
-----------------------------------------

Open the code browser for your DOS/Win16 Ghidra project.

In the menu, select ``Tools -> Function ID -> Attach existing FidDb``.

Add all of the ``.fidb`` files in the ``fidb/`` directory of this repository.

In the menu, select ``Analysis -> Auto Analyze``. Ghidra will scan over everything and annotate any C library functions that match.

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

As of this writing, you will need to set up a development version of Ghidra based on the branch at this PR, which contains several fixes to the OMF loader. The DevGuide.md in the Ghidra repository. - https://github.com/NationalSecurityAgency/ghidra/pull/4912

Find a copy of the old libraries you wish to import. I have been using the archive at https://winworldpc.com/library/dev, a very comprehensive collection of early DOS/Win16 compiler versions.

Using an emulator such as DOSBox, mount the disk image(s) and install the compiler to an empty root folder. Be sure to include *all* of the optional features, such as support for different memory modes.

Set the following environment variables (if required):

- GHIDRA_HOME: Base location for the Ghidra install. Defaults to /opt/ghidra
- GHIDRA_HEADLESS: Location of the "analyzeHeadless" script in the Ghidra install. Defaults to $GHIDRA_HOME/support/analyzeHeadless
- GHIDRA_SCRIPTS: Location of the FunctionID scripts in the Ghidra install. Defaults to $GHIDRA_HOME/Ghidra/Features/FunctionID/ghidra_scripts
- GHIDRA_PROJ: Location to create the Ghidra project used for processing. Defaults to /tmp/ghidra-proj


Finally, run ``./fidb-rip.py [shortname] [path_to_libs] [path_for_outputting_fidbs]``; this will execute all of the steps required to produce a FIDB file. You will need several gigabytes of space for the Ghidra project; approx 2GB of space for every 1MB of library data. The process involves extracting and analysing every function in the library, so will take upwards of an hour on modern hardware.
