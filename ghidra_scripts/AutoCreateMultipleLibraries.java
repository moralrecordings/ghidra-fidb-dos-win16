/* Portions copyright (c) 2019 Michael Gruhn

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
//Create multiple libraries in a single FID database
//  A root is chosen as a folder within the active project
//  Subfolders at a specific depth from this root form the roots of individual libraries
//    Library Name, Version, and Variant are created from the directory path elements
//@category FunctionID
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.TreeSet;

import generic.hash.FNV1a64MessageDigest;
import generic.hash.MessageDigest;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.db.FunctionRecord;
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;
import ghidra.feature.fid.service.FidPopulateResultReporter;
import ghidra.feature.fid.service.FidService;
import ghidra.feature.fid.service.Location;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class AutoCreateMultipleLibraries extends GhidraScript {

	private FidService service;
	private FidDB fidDb = null;
	private FidFile fidFile = null;
	private DomainFolder rootFolder = null;
	private int totalLibraries = 0;
	private boolean isCancelled = false;

	private String currentLibraryName;
	private String currentLibraryVersion;
	private String currentLibraryVariant;

	private TreeMap<Long, String> duplicatemap = null;
	private TreeMap<Long, TreeMap<String, Long>> scrubmap = null;	
	private FileOutputStream outlog = null;
	private File commonSymbolsFile = null;
	private List<String> commonSymbols = null;
	private LanguageID languageID = null;

	private MyFidPopulateResultReporter reporter = null;

	private static final int MASTER_DEPTH = 1;

	protected void outputLine(String line) {
		if (outlog != null) {
			try {
				outlog.write(line.getBytes());
				outlog.write('\n');
				outlog.flush();
			}
			catch (IOException e) {
				println("Unable to write to log");
			}
		}
		else {
			println(line);
		}
	}

	class MyFidPopulateResultReporter implements FidPopulateResultReporter {
		@Override
		public void report(FidPopulateResult result) {
			if (result == null) {
				return;
			}
			LibraryRecord libraryRecord = result.getLibraryRecord();
			String libraryFamilyName = libraryRecord.getLibraryFamilyName();
			String libraryVersion = libraryRecord.getLibraryVersion();
			String libraryVariant = libraryRecord.getLibraryVariant();
			outputLine(libraryFamilyName + ':' + libraryVersion + ':' + libraryVariant);

			outputLine(result.getTotalAttempted() + " total functions visited");
			outputLine(result.getTotalAdded() + " total functions added");
			outputLine(result.getTotalExcluded() + " total functions excluded");
			outputLine("Breakdown of exclusions:");
			for (Entry<Disposition, Integer> entry : result.getFailures().entrySet()) {
				if (entry.getKey() != Disposition.INCLUDED) {
					outputLine("    " + entry.getKey() + ": " + entry.getValue());
				}
			}
			outputLine("List of unresolved symbols:");
			TreeSet<String> symbols = new TreeSet<String>();
			for (Location location : result.getUnresolvedSymbols()) {
				symbols.add(location.getFunctionName());
			}
			for (String symbol : symbols) {
				outputLine("    " + symbol);
			}
		}

	}

	private void hashFunction(Program program, ArrayList<Long> hashList)
			throws MemoryAccessException, CancelledException {
		FunctionManager functionManager = program.getFunctionManager();
		FunctionIterator functions = functionManager.getFunctions(true);
		while (functions.hasNext()) {
			monitor.checkCanceled();
			Function func = functions.next();
			FidHashQuad hashFunction = service.hashFunction(func);
			if (hashFunction == null) {
				continue; // No body
			}
			MessageDigest digest = new FNV1a64MessageDigest();
			digest.update(func.getName().getBytes(), TaskMonitor.DUMMY);
			digest.update(hashFunction.getFullHash());
			hashList.add(digest.digestLong());
		}
	}

	private void hashListProgram(DomainFile domainFile, ArrayList<Long> hashList)
			throws VersionException, CancelledException, IOException, MemoryAccessException {
		DomainObject domainObject = null;
		try {
			domainObject = domainFile.getDomainObject(this, false, true, TaskMonitor.DUMMY);
			if (!(domainObject instanceof Program)) {
				return;
			}
			Program program = (Program) domainObject;
			hashFunction(program, hashList);
		}
		finally {
			if (domainObject != null) {
				domainObject.release(this);
			}
		}

	}

	private long calculateFinalHash(ArrayList<Long> hashList) throws CancelledException {
		MessageDigest digest = new FNV1a64MessageDigest();
		Collections.sort(hashList);
		for (int i = 0; i < hashList.size(); ++i) {
			monitor.checkCanceled();
			digest.update(hashList.get(i));
		}
		return digest.digestLong();
	}

	private boolean checkForDuplicate(ArrayList<DomainFile> programs) throws CancelledException {
		String fullName =
			currentLibraryName + ':' + currentLibraryVersion + ':' + currentLibraryVariant;
		ArrayList<Long> hashList = new ArrayList<Long>();
		for (int i = 0; i < programs.size(); ++i) {
			monitor.checkCanceled();
			try {
				Msg.info(this, "Hashing " + fullName + " " + programs.get(i).toString());
				hashListProgram(programs.get(i), hashList);
			}
			catch (VersionException ex) {
				outputLine("Version exception for " + fullName);
			}
			catch (IOException ex) {
				outputLine("IO exception for " + fullName);
			}
			catch (MemoryAccessException ex) {
				outputLine("Memory access exception for " + fullName);
			}
		}
		long val = calculateFinalHash(hashList);
		String string = duplicatemap.get(val);
		boolean res;
		if (string != null) {
			outputLine(fullName + " duplicates " + string + " 0x" + Long.toHexString(val));
			res = true;
		}
		else {
			duplicatemap.put(val, fullName);
			res = false;
		}
		return res;
	}

	private boolean detectDups(DomainFolder folder) {
		boolean isDuplicate = false;
		try {
			ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
			findPrograms(programs, folder);

			isDuplicate = checkForDuplicate(programs);
		}
		catch (CancelledException e) {
			// cancelled by user; don't notify
			isCancelled = true;
		}
		return isDuplicate;
	}

	private void parseSymbols() throws IOException, CancelledException {
		if (commonSymbolsFile == null) {
			commonSymbols = null;
			return;
		}
		BufferedReader reader = new BufferedReader(new FileReader(commonSymbolsFile));
		commonSymbols = new LinkedList<String>();
		String line = reader.readLine();
		while (line != null) {
			monitor.checkCanceled();
			if (line.length() != 0) {
				commonSymbols.add(line);
			}
			line = reader.readLine();
		}
		reader.close();
	}

	private void countLibraries(int depth, DomainFolder fold) {
		Msg.info(this, "Counting folder " + fold.toString());
		if (depth == 0) {
			totalLibraries += 1;
			return;
		}
		depth -= 1;
		DomainFolder[] subfold = fold.getFolders();
		for (DomainFolder element : subfold) {
			countLibraries(depth, element);
		}
	}

	/**
	 * Recursively finds all domain objects that are program files under a domain folder.
	 * @param programs the "return" value; found programs are placed in this collection
	 * @param myFolder the domain folder to search
	 * @throws CancelledException if the user cancels
	 */
	protected void findPrograms(ArrayList<DomainFile> programs, DomainFolder myFolder)
			throws CancelledException {
		if (myFolder == null) {
			return;
		}
		DomainFile[] files = myFolder.getFiles();
		for (DomainFile domainFile : files) {
			monitor.checkCanceled();
			if (domainFile.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
				programs.add(domainFile);
			}
		}
		DomainFolder[] folders = myFolder.getFolders();
		for (DomainFolder domainFolder : folders) {
			monitor.checkCanceled();
			findPrograms(programs, domainFolder);
		}
	}

	private void populateLibrary(DomainFolder folder) {
		ArrayList<DomainFile> programs = new ArrayList<DomainFile>();
		try {
			findPrograms(programs, folder);

			FidPopulateResult result = service.createNewLibraryFromPrograms(fidDb,
				currentLibraryName, currentLibraryVersion, currentLibraryVariant, programs, null,
				languageID, null, commonSymbols, TaskMonitor.DUMMY);
			reporter.report(result);
		}
		catch (CancelledException e) {
			isCancelled = true;
		}
		catch (MemoryAccessException e) {
			Msg.showError(this, null, "Unexpected memory access exception",
				"Please notify the Ghidra team:", e);
		}
		catch (VersionException e) {
			Msg.showError(this, null, "Version Exception",
				"One of the programs in your domain folder cannot be upgraded: " + e.getMessage());
		}
		catch (IllegalStateException e) {
			Msg.showError(this, null, "Illegal State Exception",
				"Unknown error: " + e.getMessage());
		}
		catch (IOException e) {
			Msg.showError(this, null, "FidDb IOException", "Please notify the Ghidra team:", e);
		}
	}

	private void generate(int depth, DomainFolder fold) {
		if (depth != 0) {
			depth -= 1;
			DomainFolder[] subfold = fold.getFolders();
			for (DomainFolder element : subfold) {
				generate(depth, element);
				if (isCancelled) {
					return;
				}
			}
			return;
		}
		// Reaching here, we are at library depth in the folder hierarchy
		currentLibraryName = fold.getName();
		currentLibraryVersion = "1";
		currentLibraryVariant = fold.getProjectLocator().getName();


		monitor.setMessage(
			currentLibraryName + ':' + currentLibraryVersion + ':' + currentLibraryVariant);
		boolean isDuplicate = false;
		if (duplicatemap != null) {
			isDuplicate = detectDups(fold);
		}
		if (!isDuplicate) {
			populateLibrary(fold);
		}
		monitor.incrementProgress(1);
	}

	private void scrub() {
		scrubmap = new TreeMap<Long, TreeMap<String, Long>>();

		TreeSet<Long> libCount = new TreeSet<Long>();
		TreeSet<Long> hashCount = new TreeSet<Long>();
		TreeSet<String> nameCount = new TreeSet<String>();
		for (FunctionRecord l : fidDb.findFunctionsByDomainPathSubstring("")) {
			TreeMap<String, Long> matches = scrubmap.get(l.getFullHash());
			if (matches == null) {
				matches = new TreeMap<String, Long>();
				scrubmap.put(l.getFullHash(), matches);
			}
			if (matches.containsKey(l.getName())) {
				matches.put(l.getName(), Long.valueOf(matches.get(l.getName()) + 1));
			} else {
				matches.put(l.getName(), Long.valueOf(1));
			}
			libCount.add(l.getLibraryID());
			hashCount.add(l.getFullHash());
			nameCount.add(l.getName());
		}

		for (Long funcId : scrubmap.keySet()) {
			TreeMap<String, Long> matches = scrubmap.get(funcId);
			ArrayList<String> keys = new ArrayList<String>(matches.keySet());
			Comparator<String> comp = (String s1, String s2) -> {
				Long l1 = matches.get(s1);
				Long l2 = matches.get(s2);
				if (l1 < l2)
					return 1;
				else if (l1 > l2)
					return -1;
				return s1.compareTo(s2);
			};
			Collections.sort(keys, comp);
			if (keys.size() > 1) {
				Msg.warn(this, "Collisions found for 0x" + Long.toHexString(funcId));
				for (String key : keys) {
					Msg.warn(this, "- " + key + ": " + Long.toString(matches.get(key)));
				}
				String winner = keys.get(0);
				// In the case of name collisions, disable the records
				// that have fewer matches, or are later alphabetically.
				// This is so the analyzer doesn't give you an ugly FID_CONFLICT
				// namespaced function name.
				for (FunctionRecord fr : fidDb.findFunctionsByFullHash(funcId)) {
					try {
						if (!fr.getName().equals(winner))
							fidDb.setAutoFailOnFunction(fr, true);
					} catch (IOException ex) {
						Msg.warn(this, "Couldn't set failure on function " + fr.getName());
					}
				}
			}
		}
		Msg.info(this, "We're done! " + fidDb.toString());
		Msg.info(this, "- " + Long.toString(libCount.size()) + " libraries");
		Msg.info(this, "- " + Long.toString(nameCount.size()) + " unique function names");
		Msg.info(this, "- " + Long.toString(hashCount.size()) + " unique function signatures");
			
	}

	@Override
	protected void run() throws Exception {
		service = new FidService();
		File askFile = null;

		try {
			askFile = askFile("Duplicate Results File", "OK");
			outlog = new FileOutputStream(askFile);
		}
		catch (CancelledException ex) {
			// ignore, means we use console
		}
		duplicatemap = new TreeMap<Long, String>();

		// TODO: FIXME: we can't askFile here because in headless file must exist
		File d = askDirectory("FidDB path", "OK");
		String fidbName = askString("Enter name of Fidb file", "OK");

		rootFolder =
			askProjectFolder("Select root folder containing all libraries (at a depth of " +
				Integer.toString(MASTER_DEPTH) + "):");

		File f = new File(d.getPath()+"/"+fidbName);

		FidFileManager.getInstance().createNewFidDatabase(f);
		FidFile fidFile = FidFileManager.getInstance().addUserFidFile(f);

		/*try {
			commonSymbolsFile = askFile("Common symbols file (optional):", "OK");
		}
		catch (CancelledException e) {*/
			commonSymbolsFile = null;	// Common symbols file may be null
		/*}*/
		String lang = askString("Enter LanguageID To Process", "Language ID: ");
		languageID = new LanguageID(lang);

		parseSymbols();
		reporter = new MyFidPopulateResultReporter();
		fidDb = fidFile.getFidDB(true);

		countLibraries(MASTER_DEPTH, rootFolder);
		monitor.initialize(totalLibraries);
		try {
			generate(MASTER_DEPTH, rootFolder);
			scrub();
			fidDb.saveDatabase("Saving", monitor);
		}
		finally {
			fidDb.close();
		}

		if (outlog != null) {
			outlog.close();
		}
	}

}
