/* Copyright (c) 2019 Michael Gruhn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */
//Turns off Function ID and Library Identification analysis before
//auto-analysis whilst running headless Ghidra for import and ingest
//of programs (object files/libraries) for use in creating FID libraries
//@category FunctionID
import ghidra.app.script.GhidraScript;

import java.util.Map;

public class FunctionIDHeadlessPrescriptMinimal extends GhidraScript {
	// must turn off FID and LID when analyzing libraries for FID
	// creation, in order to avoid corrupting names

	// also, it's important that your loaders have moved object file
	// sections to an appropriate height above 0x0 in order for the
	// scalar operand analyzer to run; we need to identify those
	// references to rule out scalar addresses!

	private static final String FUNCTION_ID_ANALYZER = "Function ID";
	private static final String LIBRARY_IDENTIFICATION = "Library Identification";
	private static final String DEMANGLER_ANALYZER = "Demangler";
	private static final String SCALAR_OPERAND_ANALYZER = "Scalar Operand References";
	private static final String APPLY_DATA_ARCHIVES = "Apply Data Archives";
	private static final String ASCII_STRINGS = "ASCII Strings";
	private static final String DECOMPILER_SWTICH_ANALYSIS = "Decompiler Switch Analysis";
	private static final String EMBEDDED_MEDIA = "Embedded Media";

	@Override
	protected void run() throws Exception {
		Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
		if (options.containsKey(FUNCTION_ID_ANALYZER)) {
			setAnalysisOption(currentProgram, FUNCTION_ID_ANALYZER, "false");
		}
		if (options.containsKey(LIBRARY_IDENTIFICATION)) {
			setAnalysisOption(currentProgram, LIBRARY_IDENTIFICATION, "false");
		}
		if (options.containsKey(DEMANGLER_ANALYZER)) {
			setAnalysisOption(currentProgram, DEMANGLER_ANALYZER, "false");
		}
		if (options.containsKey(SCALAR_OPERAND_ANALYZER)) {
			setAnalysisOption(currentProgram, SCALAR_OPERAND_ANALYZER, "true");
		}
		if (options.containsKey(APPLY_DATA_ARCHIVES)) {
			setAnalysisOption(currentProgram, APPLY_DATA_ARCHIVES, "false");
		}
		if (options.containsKey(ASCII_STRINGS)) {
			setAnalysisOption(currentProgram, ASCII_STRINGS, "false");
		}
		if (options.containsKey(DECOMPILER_SWTICH_ANALYSIS)) {
			setAnalysisOption(currentProgram, DECOMPILER_SWTICH_ANALYSIS, "false");
		}
		if (options.containsKey(EMBEDDED_MEDIA)) {
			setAnalysisOption(currentProgram, EMBEDDED_MEDIA, "false");
		}
	}
}
