#!/usr/bin/env python3

import argparse
import os
import pathlib
import subprocess

GHIDRA_HOME = os.getenv("GHIDRA_HOME", "/opt/ghidra")
GHIDRA_HEADLESS = os.getenv("GHIDRA_HEADLESS", f"{GHIDRA_HOME}/support/analyzeHeadless")
GHIDRA_SCRIPTS = os.getenv("GHIDRA_SCRIPTS", f"{GHIDRA_HOME}/Ghidra/Features/FunctionID/ghidra_scripts")
GHIDRA_PROJ = os.getenv("GHIDRA_PROJ", "/tmp/ghidra-proj")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('lib_name', help='Name of library collection')
    parser.add_argument('lib_path', help='Path to object/library files')
    parser.add_argument('fidb_path', help='Output path for created FIDB files')

    parser.add_argument("--skip-load", help='Skip loading step', action='store_true') 
    parser.add_argument("--skip-analyse", help='Skip analysis step', action='store_true')
    parser.add_argument("--skip-fidb", help='Skip FIDB creation step', action='store_true')
#    parser.add_argument("--skip-pack", help='Skip FIDB packing step', action='store_true')
    parser.add_argument("--delete", help='Delete project after completion', action='store_true')
    parser.add_argument("--duplicate-log", help="Output text file for duplicate logs", default="/tmp/fidb-duplicates.log")

    args = parser.parse_args()

    os.makedirs(GHIDRA_PROJ, exist_ok=True)
    os.makedirs(args.fidb_path, exist_ok=True)

    fidb_path = os.path.abspath(args.fidb_path)

    if not args.skip_load:
        print("==== Loading libraries into a new Ghidra project")
        subprocess.check_call([GHIDRA_HEADLESS, GHIDRA_PROJ, args.lib_name, "-noanalysis", "-scriptPath", "ghidra_scripts", "-preScript", "ImportFromFileSystem.java", args.lib_path, "x86:LE:16:Real Mode"])

    if not args.skip_analyse:
        print("==== Auto-analysing all objects")
        subprocess.check_call([GHIDRA_HEADLESS, GHIDRA_PROJ, args.lib_name, "-scriptPath", "ghidra_scripts", "-process", "*", "-recursive", "-preScript", "FunctionIDHeadlessPrescriptMinimal.java", "-postScript", "FunctionIDHeadlessPostscript.java"])

    if not args.skip_fidb:
        print("==== Generating a FIDB")
        pathlib.Path(args.duplicate_log).touch() 
        subprocess.check_call([GHIDRA_HEADLESS, GHIDRA_PROJ, args.lib_name, "-noanalysis", "-scriptPath", "ghidra_scripts","-preScript", "AutoCreateMultipleLibraries.java", args.duplicate_log, fidb_path, f"{args.lib_name}.fidb", "/", "x86:LE:16:Real Mode"])

#    if not args.skip_pack:
#        print("==== Packing the FIDB")
#        subprocess.check_call([GHIDRA_HEADLESS, GHIDRA_PROJ, args.lib_name, "-noanalysis", "-preScript", "RepackFid.java", f"{fidb_path}/{args.lib_name}.raw.fidb", f"{fidb_path}/{args.lib_name}.fidb"])


# generate a FunctionID database, scrub out non-essential entries
# mkdir fidb
# touch duplicate_results.txt
# touch common.txt
# ~/Development/ghidra/Ghidra/RuntimeScripts/Linux/support/analyzeHeadless /home/scott/Reversing msvc152c -noanalysis -scriptPath ghidra_scripts -preScript AutoCreateMultipleLibraries.java duplicate_results.txt true fidb "msvc152c.fidb" "/" common.txt "x86:LE:16:Real Mode"

# pack the FunctionID database
# ~/Development/ghidra/Ghidra/RuntimeScripts/Linux/support/analyzeHeadless /home/scott/Reversing msvc152c -noanalysis -preScript RepackFid.java  
