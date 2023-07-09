/*
 * Autopsy Forensic Browser
 *
 * Copyright 2020-2021 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.autopsy.modules.lleappanalyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.ArrayList;
import java.util.Locale;
import java.util.logging.Level;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.commons.io.FilenameUtils;
import org.openide.modules.InstalledFileLocator;
import org.openide.util.NbBundle;
import org.sleuthkit.autopsy.casemodule.Case;
import static org.sleuthkit.autopsy.casemodule.Case.getCurrentCase;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.coreutils.ExecUtil;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.PlatformUtil;
import org.sleuthkit.autopsy.datamodel.ContentUtils;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProcessTerminator;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestMessage;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.autopsy.ingest.IngestModule.IngestModuleException;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.LocalFilesDataSource;
import org.sleuthkit.datamodel.ReadContentInputStream;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Data source ingest module that runs lLeapp against logical iOS files.
 */
public class LLeappAnalyzerIngestModule implements DataSourceIngestModule {

    private static final Logger logger = Logger.getLogger(LLeappAnalyzerIngestModule.class.getName());
    private static final String MODULE_NAME = LLeappAnalyzerModuleFactory.getModuleName();

    private static final String LLEAPP = "lLeapp"; //NON-NLS
    private static final String LLEAPP_FS = "fs_"; //NON-NLS
    private static final String LLEAPP_EXECUTABLE = "lleapp.exe";//NON-NLS
    private static final String LLEAPP_PATHS_FILE = "lLeapp_paths.txt"; //NON-NLS
    private static final String BASE_DIR_NAME = "modules";
    
    private static final String XMLFILE = "lleapp-artifact-attribute-reference.xml"; //NON-NLS

    private File lLeappExecutable;

    private IngestJobContext context;

    private LeappFileProcessor lLeappFileProcessor;

    LLeappAnalyzerIngestModule() {
        // This constructor is intentionally empty. Nothing special is needed here.     
    }

    @NbBundle.Messages({
        "LLeappAnalyzerIngestModule.executable.not.found=lLeapp Executable Not Found.",
        "LLeappAnalyzerIngestModule.requires.windows=lLeapp module requires windows.",
        "LLeappAnalyzerIngestModule.error.lleapp.file.processor.init=Failure to initialize lLeappProcessFile"})
    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        this.context = context;

        if (false == PlatformUtil.is64BitOS()) {
            throw new IngestModuleException(NbBundle.getMessage(this.getClass(), "AleappAnalyzerIngestModule.not.64.bit.os"));
        }

        if (false == PlatformUtil.isWindowsOS()) {
            throw new IngestModuleException(Bundle.LLeappAnalyzerIngestModule_requires_windows());
        }

        try {
            lLeappFileProcessor = new LeappFileProcessor(XMLFILE, LLeappAnalyzerModuleFactory.getModuleName(), LLEAPP, context);
        } catch (IOException | IngestModuleException | NoCurrentCaseException ex) {
            throw new IngestModuleException(Bundle.LLeappAnalyzerIngestModule_error_lleapp_file_processor_init(), ex);
        }

        try {
            lLeappExecutable = locateExecutable(LLEAPP_EXECUTABLE);
        } catch (FileNotFoundException exception) {
            logger.log(Level.WARNING, "lLeapp executable not found.", exception); //NON-NLS
            throw new IngestModuleException(Bundle.LLeappAnalyzerIngestModule_executable_not_found(), exception);
        }

    }

    @NbBundle.Messages({
        "LLeappAnalyzerIngestModule.error.running.lLeapp=Error running lLeapp, see log file.",
        "LLeappAnalyzerIngestModule.error.creating.output.dir=Error creating lLeapp module output directory.",
        "LLeappAnalyzerIngestModule.running.lLeapp=Running lLeapp",
        "LLeappAnalyzerIngestModule_processing_lLeapp_results=Processing lLeapp results",
        "LLeappAnalyzerIngestModule.has.run=lLeapp",
        "LLeappAnalyzerIngestModule.lLeapp.cancelled=lLeapp run was canceled",
        "LLeappAnalyzerIngestModule.completed=lLeapp Processing Completed",
        "LLeappAnalyzerIngestModule.report.name=lLeapp Html Report"})
    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress statusHelper) {

        statusHelper.switchToIndeterminate();
        statusHelper.progress(Bundle.LLeappAnalyzerIngestModule_running_lLeapp());

        Case currentCase = Case.getCurrentCase();
        Path tempOutputPath = Paths.get(currentCase.getTempDirectory(), LLEAPP, LLEAPP_FS + dataSource.getId());
        try {
            Files.createDirectories(tempOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating lLeapp output directory %s", tempOutputPath.toString()), ex);
            writeErrorMsgToIngestInbox();
            return ProcessResult.ERROR;
        }

        List<String> lLeappPathsToProcess;
        ProcessBuilder lLeappCommand = buildlLeappListCommand(tempOutputPath);
        try {
            int result = ExecUtil.execute(lLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.SEVERE, String.format("Error when trying to execute lLeapp program getting file paths to search for result is %d", result));
                writeErrorMsgToIngestInbox();
                return ProcessResult.ERROR;
            }
            lLeappPathsToProcess = loadAleappPathFile(tempOutputPath);
            if (lLeappPathsToProcess.isEmpty()) {
                logger.log(Level.SEVERE, String.format("Error getting file paths to search, list is empty"));
                writeErrorMsgToIngestInbox();
                return ProcessResult.ERROR;
            }
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute lLeapp program getting file paths to search"), ex);
            writeErrorMsgToIngestInbox();
            return ProcessResult.ERROR;
        }

        if ((context.getDataSource() instanceof LocalFilesDataSource)) {
            /*
             * The data source may be local files from an iOS file system, or it
             * may be a tarred/ZIP of an iOS file system. If it is the latter,
             * extract the files we need to process.
             */
            List<AbstractFile> lLeappFilesToProcess = LeappFileProcessor.findLeappFilesToProcess(dataSource);
            if (!lLeappFilesToProcess.isEmpty()) {
                statusHelper.switchToDeterminate(lLeappFilesToProcess.size());
                Integer filesProcessedCount = 0;
                for (AbstractFile lLeappFile : lLeappFilesToProcess) {
                    processLLeappFile(dataSource, currentCase, statusHelper, filesProcessedCount, lLeappFile);
                    filesProcessedCount++;
                }
            }
        }

        statusHelper.switchToIndeterminate();
        statusHelper.progress(Bundle.LLeappAnalyzerIngestModule_processing_lLeapp_results());
        extractFilesFromDataSource(dataSource, lLeappPathsToProcess, tempOutputPath);
        processLLeappFs(dataSource, currentCase, statusHelper, tempOutputPath.toString());

        IngestMessage message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                Bundle.LLeappAnalyzerIngestModule_has_run(),
                Bundle.LLeappAnalyzerIngestModule_completed());
        IngestServices.getInstance().postMessage(message);
        return ProcessResult.OK;
    }

    /**
     * Process a file from a logical image using the lLeapp program
     *
     * @param dataSource          datasource to process
     * @param currentCase         current case that is being worked on
     * @param statusHelper        show progress and update what is being
     *                            processed
     * @param filesProcessedCount number of files that have been processed
     * @param lLeappFile          the abstract file to process
     */
    private void processLLeappFile(Content dataSource, Case currentCase, DataSourceIngestModuleProgress statusHelper, int filesProcessedCount,
            AbstractFile lLeappFile) {
        statusHelper.progress(NbBundle.getMessage(this.getClass(), "LLeappAnalyzerIngestModule.processing.file", lLeappFile.getName()), filesProcessedCount);
        String currentTime = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss z", Locale.US).format(System.currentTimeMillis());//NON-NLS
        Path moduleOutputPath = Paths.get(currentCase.getModuleDirectory(), LLEAPP, currentTime);
        try {
            Files.createDirectories(moduleOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating lLeapp output directory %s", moduleOutputPath.toString()), ex);
            return;
        }

        ProcessBuilder lLeappCommand = buildlLeappCommand(moduleOutputPath, lLeappFile.getLocalAbsPath(), lLeappFile.getNameExtension());
        try {
            int result = ExecUtil.execute(lLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.WARNING, String.format("Error when trying to execute lLeapp program getting file paths to search for result is %d", result));
                return;
            }

            addLLeappReportToReports(moduleOutputPath, currentCase);

        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute lLeapp program against file %s", lLeappFile.getLocalAbsPath()), ex);
            return;
        }

        if (context.dataSourceIngestIsCancelled()) {
            logger.log(Level.INFO, "lLeapp Analyser ingest module run was canceled"); //NON-NLS
            return;
        }

        lLeappFileProcessor.processFiles(dataSource, moduleOutputPath, lLeappFile, statusHelper);
    }

    /**
     * Process a image/directory using the lLeapp program
     *
     * @param dataSource         datasource to process
     * @param currentCase        current case being procesed
     * @param statusHelper       show progress and update what is being
     *                           processed
     * @param directoryToProcess directory to run lLeapp against
     */
    private void processLLeappFs(Content dataSource, Case currentCase, DataSourceIngestModuleProgress statusHelper, String directoryToProcess) {
        statusHelper.progress(NbBundle.getMessage(this.getClass(), "LLeappAnalyzerIngestModule.processing.filesystem"));
        String currentTime = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss z", Locale.US).format(System.currentTimeMillis());//NON-NLS
        Path moduleOutputPath = Paths.get(currentCase.getModuleDirectory(), LLEAPP, currentTime);
        try {
            Files.createDirectories(moduleOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating lLeapp output directory %s", moduleOutputPath.toString()), ex);
            return;
        }

        ProcessBuilder lLeappCommand = buildlLeappCommand(moduleOutputPath, directoryToProcess, "fs");
        try {
            int result = ExecUtil.execute(lLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.WARNING, String.format("Error when trying to execute lLeapp program getting file paths to search for result is %d", result));
                return;
            }

            addLLeappReportToReports(moduleOutputPath, currentCase);

        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute lLeapp program against file system"), ex);
            return;
        }

        if (context.dataSourceIngestIsCancelled()) {
            logger.log(Level.INFO, "lLeapp Analyser ingest module run was canceled"); //NON-NLS
            return;
        }

        lLeappFileProcessor.processFileSystem(dataSource, moduleOutputPath, statusHelper);
    }

    /**
     * Build the lLeapp command to run
     *
     * @param moduleOutputPath     output path for the lLeapp program.
     * @param sourceFilePath       where the source files to process reside.
     * @param lLeappFileSystemType the filesystem type to process
     *
     * @return the command to execute
     */
    private ProcessBuilder buildlLeappCommand(Path moduleOutputPath, String sourceFilePath, String lLeappFileSystemType) {

        ProcessBuilder processBuilder = buildProcessWithRunAsInvoker(
                lLeappExecutable.getAbsolutePath(), //NON-NLS
                "-t", lLeappFileSystemType, //NON-NLS
                "-i", sourceFilePath, //NON-NLS
                "-o", moduleOutputPath.toString(),
                "-w"
        );
        processBuilder.redirectError(moduleOutputPath.resolve("lLeapp_err.txt").toFile());  //NON-NLS
        processBuilder.redirectOutput(moduleOutputPath.resolve("lLeapp_out.txt").toFile());  //NON-NLS
        return processBuilder;
    }

    private ProcessBuilder buildlLeappListCommand(Path moduleOutputPath) {

        ProcessBuilder processBuilder = buildProcessWithRunAsInvoker(
                lLeappExecutable.getAbsolutePath(), //NON-NLS
                "-p"
        );
        // leapp process creates a text file in addition to outputting to stdout.
        processBuilder.directory(moduleOutputPath.toFile());
        processBuilder.redirectError(moduleOutputPath.resolve("lLeapp_paths_error.txt").toFile());  //NON-NLS
        processBuilder.redirectOutput(moduleOutputPath.resolve("lLeapp_paths.txt").toFile());  //NON-NLS
        return processBuilder;
    }

    static private ProcessBuilder buildProcessWithRunAsInvoker(String... commandLine) {
        ProcessBuilder processBuilder = new ProcessBuilder(commandLine);
        /*
         * Add an environment variable to force lLeapp to run with the same
         * permissions Autopsy uses.
         */
        processBuilder.environment().put("__COMPAT_LAYER", "RunAsInvoker"); //NON-NLS
        return processBuilder;
    }

    private static File locateExecutable(String executableName) throws FileNotFoundException {
        String executableToFindName = Paths.get(BASE_DIR_NAME, LLEAPP, executableName).toString();

        File exeFile = InstalledFileLocator.getDefault().locate(executableToFindName, LLeappAnalyzerIngestModule.class.getPackage().getName(), false);
        if (null == exeFile || exeFile.canExecute() == false) {
            throw new FileNotFoundException(executableName + " executable not found.");
        }
        return exeFile;
    }

    /**
     * Find the index.html file in the lLeapp output directory so it can be
     * added to reports
     */
    private void addLLeappReportToReports(Path lLeappOutputDir, Case currentCase) {
        List<String> allIndexFiles = new ArrayList<>();

        try (Stream<Path> walk = Files.walk(lLeappOutputDir)) {

            allIndexFiles = walk.map(x -> x.toString())
                    .filter(f -> f.toLowerCase().endsWith("index.html")).collect(Collectors.toList());

            if (!allIndexFiles.isEmpty()) {
                // Check for existance of directory that holds report data if does not exist then report contains no data
                String filePath = FilenameUtils.getFullPathNoEndSeparator(allIndexFiles.get(0));
                File dataFilesDir = new File(Paths.get(filePath, "_TSV Exports").toString());
                if (dataFilesDir.exists()) {
                    currentCase.addReport(allIndexFiles.get(0), MODULE_NAME, Bundle.LLeappAnalyzerIngestModule_report_name());
                }
            }

        } catch (IOException | UncheckedIOException | TskCoreException ex) {
            // catch the error and continue on as report is not added
            logger.log(Level.WARNING, String.format("Error finding index file in path %s", lLeappOutputDir.toString()), ex);
        }

    }

    /*
     * Reads the lLeapp paths file to get the paths that we want to extract
     *
     */
    private List<String> loadAleappPathFile(Path moduleOutputPath) throws FileNotFoundException, IOException {
        List<String> lLeappPathsToProcess = new ArrayList<>();

        Path filePath = Paths.get(moduleOutputPath.toString(), LLEAPP_PATHS_FILE);

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath.toString()))) {
            String line = reader.readLine();
            while (line != null) {
                if (line.contains("path list generation") || line.length() < 2) {
                    line = reader.readLine();
                    continue;
                }
                lLeappPathsToProcess.add(line.trim());
                line = reader.readLine();
            }
        }

        return lLeappPathsToProcess;
    }

    private void extractFilesFromDataSource(Content dataSource, List<String> lLeappPathsToProcess, Path moduleOutputPath) {
        FileManager fileManager = getCurrentCase().getServices().getFileManager();

        for (String fullFilePath : lLeappPathsToProcess) {

            if (context.dataSourceIngestIsCancelled()) {
                logger.log(Level.INFO, "lLeapp Analyser ingest module run was canceled"); //NON-NLS
                break;
            }

            String ffp = fullFilePath.replaceAll("\\*", "%");
            ffp = FilenameUtils.normalize(ffp, true);
            String fileName = FilenameUtils.getName(ffp);
            String filePath = FilenameUtils.getPath(ffp);

            List<AbstractFile> lLeappFiles = new ArrayList<>();
            try {
                if (filePath.isEmpty()) {
                    lLeappFiles = fileManager.findFiles(dataSource, fileName); //NON-NLS                
                } else {
                    lLeappFiles = fileManager.findFiles(dataSource, fileName, filePath); //NON-NLS
                }
            } catch (TskCoreException ex) {
                logger.log(Level.WARNING, "No files found to process"); //NON-NLS
                return;
            }

            for (AbstractFile lLeappFile : lLeappFiles) {
                Path parentPath = Paths.get(moduleOutputPath.toString(), lLeappFile.getParentPath());
                File fileParentPath = new File(parentPath.toString());

                extractFileToOutput(dataSource, lLeappFile, fileParentPath, parentPath);
            }
        }
    }

    private void extractFileToOutput(Content dataSource, AbstractFile lLeappFile, File fileParentPath, Path parentPath) {
        if (fileParentPath.exists()) {
            if (!lLeappFile.isDir()) {
                writelLeappFile(dataSource, lLeappFile, fileParentPath.toString());
            } else {
                try {
                    Files.createDirectories(Paths.get(parentPath.toString(), lLeappFile.getName()));
                } catch (IOException ex) {
                    logger.log(Level.INFO, String.format("Error creating lLeapp output directory %s", parentPath.toString()), ex);
                }
            }
        } else {
            try {
                Files.createDirectories(parentPath);
            } catch (IOException ex) {
                logger.log(Level.INFO, String.format("Error creating lLeapp output directory %s", parentPath.toString()), ex);
            }
            if (!lLeappFile.isDir()) {
                writelLeappFile(dataSource, lLeappFile, fileParentPath.toString());
            } else {
                try {
                    Files.createDirectories(Paths.get(parentPath.toString(), lLeappFile.getName()));
                } catch (IOException ex) {
                    logger.log(Level.INFO, String.format("Error creating lLeapp output directory %s", parentPath.toString()), ex);
                }
            }
        }
    }

    private void writelLeappFile(Content dataSource, AbstractFile lLeappFile, String parentPath) {
        String fileName = lLeappFile.getName().replace(":", "-");
        if (!fileName.matches(".") && !fileName.matches("..") && !fileName.toLowerCase().endsWith("-slack")) {
            Path filePath = Paths.get(parentPath, fileName);
            File localFile = new File(filePath.toString());
            try {
                ContentUtils.writeToFile(lLeappFile, localFile, context::dataSourceIngestIsCancelled);
            } catch (ReadContentInputStream.ReadContentInputStreamException ex) {
                logger.log(Level.WARNING, String.format("Error reading file '%s' (id=%d).",
                        lLeappFile.getName(), lLeappFile.getId()), ex); //NON-NLS
            } catch (IOException ex) {
                logger.log(Level.WARNING, String.format("Error writing file local file '%s' (id=%d).",
                        filePath.toString(), lLeappFile.getId()), ex); //NON-NLS
            }
        }
    }

    /**
     * Writes a generic error message to the ingest inbox, directing the user to
     * consult the application log fpor more details.
     */
    private void writeErrorMsgToIngestInbox() {
        IngestMessage message = IngestMessage.createMessage(IngestMessage.MessageType.ERROR,
                MODULE_NAME,
                Bundle.LLeappAnalyzerIngestModule_error_running_lLeapp());
        IngestServices.getInstance().postMessage(message);
    }

}
