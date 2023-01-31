import ghidra.app.script.GhidraScript;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.model.DomainFolder;
import ghidra.plugins.importer.batch.BatchInfo;
import ghidra.plugins.importer.tasks.ImportBatchTask;
import ghidra.util.*;
import java.io.File;
import java.io.FilenameFilter;

public class ImportFromFileSystem extends GhidraScript {

        @Override
        protected void run() throws Exception {
                DomainFolder destinationFolder = getProjectRootFolder();
                File targetDir = askDirectory("Choose directory with target libraries", "Select");
                File[] targetFiles = targetDir.listFiles(new FilenameFilter() {
                        public boolean accept(File dir, String name) {
                                return name.toLowerCase().endsWith(".lib") || name.toLowerCase().endsWith(".obj");
                        }
                });
                
                BatchInfo batchInfo = new BatchInfo();
                batchInfo.setMaxDepth(2);
                for (File file : targetFiles) {
                        FSRL fsrl = FSRL.fromString("file://" + file.getAbsolutePath());
                        FileSystemService fileSystemService = FileSystemService.getInstance();
                        //FileSystemRef ref = fileSystemService.probeFileForFilesystem(fsrl, monitor, null);
                        Msg.info(this, "Adding source file " + file.getAbsolutePath());
                        batchInfo.addFile(fsrl, monitor);
                }

                ImportBatchTask task = new ImportBatchTask(batchInfo, destinationFolder, null, true, false);
                Msg.info(this, "Running the batch import...");
                task.run(monitor);


        }
}
