/*
 * Autopsy Forensic Browser
 *
 * Copyright 2021 Basis Technology Corp.
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
package org.sleuthkit.autopsy.modules.cleappanalyzer;

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
 * Data source ingest module that runs cLeapp against logical iOS files.
 */
public class CLeappAnalyzerIngestModule implements DataSourceIngestModule {

    private static final Logger logger = Logger.getLogger(CLeappAnalyzerIngestModule.class.getName());
    private static final String MODULE_NAME = CLeappAnalyzerModuleFactory.getModuleName();

    private static final String CLEAPP = "cLeapp"; //NON-NLS
    private static final String CLEAPP_FS = "fs"; //NON-NLS
    private static final String CLEAPP_EXECUTABLE = "cLeapp.exe";//NON-NLS
    private static final String CLEAPP_PATHS_FILE = "cLeapp_paths.txt"; //NON-NLS
    private static final String BASE_DIR_NAME = "modules";
    
    private static final String XMLFILE = "cleap-artifact-attribute-reference.xml"; //NON-NLS


    private File cLeappExecutable;

    private IngestJobContext context;

    private LeappFileProcessor cLeappFileProcessor;

    CLeappAnalyzerIngestModule() {
        // This constructor is intentionally empty. Nothing special is needed here.     
    }

    @NbBundle.Messages({
        "CLeappAnalyzerIngestModule.executable.not.found=cLeapp Executable Not Found.",
        "CLeappAnalyzerIngestModule.requires.windows=cLeapp module requires windows.",
        "CLeappAnalyzerIngestModule.error.ileapp.file.processor.init=Failure to initialize cLeappProcessFile"})
    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        this.context = context;

        if (false == PlatformUtil.is64BitOS()) {
            throw new IngestModuleException(NbBundle.getMessage(this.getClass(), "CleappAnalyzerIngestModule.not.64.bit.os"));
        }

        if (false == PlatformUtil.isWindowsOS()) {
            throw new IngestModuleException(Bundle.CLeappAnalyzerIngestModule_requires_windows());
        }

        try {
            cLeappFileProcessor = new LeappFileProcessor(XMLFILE, CLeappAnalyzerModuleFactory.getModuleName());
        } catch (IOException | IngestModuleException | NoCurrentCaseException ex) {
            throw new IngestModuleException(Bundle.CLeappAnalyzerIngestModule_error_ileapp_file_processor_init(), ex);
        }

        try {
            cLeappExecutable = locateExecutable(CLEAPP_EXECUTABLE);
        } catch (FileNotFoundException exception) {
            logger.log(Level.WARNING, "cLeapp executable not found.", exception); //NON-NLS
            throw new IngestModuleException(Bundle.CLeappAnalyzerIngestModule_executable_not_found(), exception);
        }

    }

    @NbBundle.Messages({
        "CLeappAnalyzerIngestModule.error.running.cLeapp=Error running cLeapp, see log file.",
        "CLeappAnalyzerIngestModule.error.creating.output.dir=Error creating cLeapp module output directory.",
        "CLeappAnalyzerIngestModule.starting.cLeapp=Starting cLeapp",
        "CLeappAnalyzerIngestModule.running.cLeapp=Running cLeapp",
        "CLeappAnalyzerIngestModule.has.run=cLeapp",
        "CLeappAnalyzerIngestModule.cLeapp.cancelled=cLeapp run was canceled",
        "CLeappAnalyzerIngestModule.completed=cLeapp Processing Completed",
        "CLeappAnalyzerIngestModule.report.name=cLeapp Html Report"})
    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress statusHelper) {

        Case currentCase = Case.getCurrentCase();
        Path tempOutputPath = Paths.get(currentCase.getTempDirectory(), CLEAPP, CLEAPP_FS + dataSource.getId());
        try {
            Files.createDirectories(tempOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating cLeapp output directory %s", tempOutputPath.toString()), ex);
            return ProcessResult.ERROR;
        }

        List<String> cLeappPathsToProcess = new ArrayList<>();
        ProcessBuilder cLeappCommand = buildcLeappListCommand(tempOutputPath);
        try {
            int result = ExecUtil.execute(cLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.SEVERE, String.format("Error when trying to execute cLeapp program getting file paths to search for result is %d", result));
                return ProcessResult.ERROR;
            }
            cLeappPathsToProcess = loadCleappPathFile(tempOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute cLeapp program getting file paths to search"), ex);
            return ProcessResult.ERROR;
        }

        statusHelper.progress(Bundle.CLeappAnalyzerIngestModule_starting_cLeapp(), 0);

        List<AbstractFile> cLeappFilesToProcess = new ArrayList<>();

        if (!(context.getDataSource() instanceof LocalFilesDataSource)) {
            extractFilesFromImage(dataSource, cLeappPathsToProcess, tempOutputPath);
            statusHelper.switchToDeterminate(cLeappFilesToProcess.size());
            processCLeappFs(dataSource, currentCase, statusHelper, tempOutputPath.toString());
        } else {
            cLeappFilesToProcess = LeappFileProcessor.findLeappFilesToProcess(dataSource);
            statusHelper.switchToDeterminate(cLeappFilesToProcess.size());

            Integer filesProcessedCount = 0;
            for (AbstractFile cLeappFile : cLeappFilesToProcess) {
                processCLeappFile(dataSource, currentCase, statusHelper, filesProcessedCount, cLeappFile);
                filesProcessedCount++;
            }
            // Process the logical image as a fs in cLeapp to make sure this is not a logical fs that was added
            extractFilesFromImage(dataSource, cLeappPathsToProcess, tempOutputPath);
            processCLeappFs(dataSource, currentCase, statusHelper, tempOutputPath.toString());
        }

        IngestMessage message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                Bundle.CLeappAnalyzerIngestModule_has_run(),
                Bundle.CLeappAnalyzerIngestModule_completed());
        IngestServices.getInstance().postMessage(message);
        return ProcessResult.OK;
    }

    /**
     * Process a file from a logical image using the cLeapp program
     * @param dataSource datasource to process
     * @param currentCase current case that is being worked on
     * @param statusHelper show progress and update what is being processed
     * @param filesProcessedCount number of files that have been processed
     * @param cLeappFile the abstract file to process
     */
    private void processCLeappFile(Content dataSource, Case currentCase, DataSourceIngestModuleProgress statusHelper, int filesProcessedCount,
            AbstractFile cLeappFile) {
        String currentTime = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss z", Locale.US).format(System.currentTimeMillis());//NON-NLS
        Path moduleOutputPath = Paths.get(currentCase.getModuleDirectory(), CLEAPP, currentTime);
        try {
            Files.createDirectories(moduleOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating cLeapp output directory %s", moduleOutputPath.toString()), ex);
            return;
        }

        statusHelper.progress(NbBundle.getMessage(this.getClass(), "CLeappAnalyzerIngestModule.processing.file", cLeappFile.getName()), filesProcessedCount);
        ProcessBuilder cLeappCommand = buildcLeappCommand(moduleOutputPath, cLeappFile.getLocalAbsPath(), cLeappFile.getNameExtension());
        try {
            int result = ExecUtil.execute(cLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.WARNING, String.format("Error when trying to execute cLeapp program getting file paths to search for result is %d", result));
                return;
            }

            addLeappReportToReports(moduleOutputPath, currentCase);

        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute cLeapp program against file %s", cLeappFile.getLocalAbsPath()), ex);
            return;
        }

        if (context.dataSourceIngestIsCancelled()) {
            logger.log(Level.INFO, "cLeapp Analyser ingest module run was canceled"); //NON-NLS
            return;
        }

        ProcessResult fileProcessorResult = cLeappFileProcessor.processFiles(dataSource, moduleOutputPath, cLeappFile);

        if (fileProcessorResult == ProcessResult.ERROR) {
            return;
        }
    }

    /**
     * Process a image/directory using the cLeapp program
     * @param dataSource datasource to process
     * @param currentCase current case being procesed
     * @param statusHelper show progress and update what is being processed
     * @param directoryToProcess directory to run cLeapp against
     */
    private void processCLeappFs(Content dataSource, Case currentCase, DataSourceIngestModuleProgress statusHelper, String directoryToProcess) {
        String currentTime = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss z", Locale.US).format(System.currentTimeMillis());//NON-NLS
        Path moduleOutputPath = Paths.get(currentCase.getModuleDirectory(), CLEAPP, currentTime);
        try {
            Files.createDirectories(moduleOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating cLeapp output directory %s", moduleOutputPath.toString()), ex);
            return;
        }

        statusHelper.progress(NbBundle.getMessage(this.getClass(), "CLeappAnalyzerIngestModule.processing.filesystem"));
        ProcessBuilder cLeappCommand = buildcLeappCommand(moduleOutputPath, directoryToProcess, "fs");
        try {
            int result = ExecUtil.execute(cLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.WARNING, String.format("Error when trying to execute cLeapp program getting file paths to search for result is %d", result));
                return;
            }

            addLeappReportToReports(moduleOutputPath, currentCase);

        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute cLeapp program against file system"), ex);
            return;
        }

        if (context.dataSourceIngestIsCancelled()) {
            logger.log(Level.INFO, "cLeapp Analyser ingest module run was canceled"); //NON-NLS
            return;
        }

        ProcessResult fileProcessorResult = cLeappFileProcessor.processFileSystem(dataSource, moduleOutputPath);

        if (fileProcessorResult == ProcessResult.ERROR) {
            return;
        }

    }



    /**
     * Build the cLeapp command to run
     * 
     * @param moduleOutputPath output path for the cLeapp program.
     * @param sourceFilePath where the source files to process reside.
     * @param cLeappFileSystemType the filesystem type to process
     * 
     * @return the command to execute
     */
    private ProcessBuilder buildcLeappCommand(Path moduleOutputPath, String sourceFilePath, String cLeappFileSystemType) {

        ProcessBuilder processBuilder = buildProcessWithRunAsInvoker(
                "\"" + cLeappExecutable + "\"", //NON-NLS
                "-t", cLeappFileSystemType, //NON-NLS
                "-i", sourceFilePath, //NON-NLS
                "-o", moduleOutputPath.toString(),
                "-w"
        );
        processBuilder.redirectError(moduleOutputPath.resolve("cLeapp_err.txt").toFile());  //NON-NLS
        processBuilder.redirectOutput(moduleOutputPath.resolve("cLeapp_out.txt").toFile());  //NON-NLS
        return processBuilder;
    }

    private ProcessBuilder buildcLeappListCommand(Path moduleOutputPath) {

        ProcessBuilder processBuilder = buildProcessWithRunAsInvoker(
                "\"" + cLeappExecutable + "\"", //NON-NLS
                "-p"
        );
        processBuilder.redirectError(moduleOutputPath.resolve("cLeapp_paths_error.txt").toFile());  //NON-NLS
        processBuilder.redirectOutput(moduleOutputPath.resolve("cLeapp_paths.txt").toFile());  //NON-NLS
        return processBuilder;
    }

    static private ProcessBuilder buildProcessWithRunAsInvoker(String... commandLine) {
        ProcessBuilder processBuilder = new ProcessBuilder(commandLine);
        /*
         * Add an environment variable to force cLeapp to run with
         * the same permissions Autopsy uses.
         */
        processBuilder.environment().put("__COMPAT_LAYER", "RunAsInvoker"); //NON-NLS
        return processBuilder;
    }

    private static File locateExecutable(String executableName) throws FileNotFoundException {
        String executableToFindName = Paths.get(BASE_DIR_NAME, CLEAPP, executableName).toString();

        File exeFile = InstalledFileLocator.getDefault().locate(executableToFindName, CLeappAnalyzerIngestModule.class.getPackage().getName(), false);
        if (null == exeFile || exeFile.canExecute() == false) {
            throw new FileNotFoundException(executableName + " executable not found.");
        }
        return exeFile;
    }

    /**
     * Find the index.html file in the cLeapp output directory so it can be
     * added to reports
     */
    private void addLeappReportToReports(Path cLeappOutputDir, Case currentCase) {
        List<String> allIndexFiles = new ArrayList<>();

        try (Stream<Path> walk = Files.walk(cLeappOutputDir)) { 

            allIndexFiles = walk.map(x -> x.toString())
                    .filter(f -> f.toLowerCase().endsWith("index.html")).collect(Collectors.toList());

            if (!allIndexFiles.isEmpty()) {
                // Check for existance of directory that holds report data if does not exist then report contains no data
                String filePath = FilenameUtils.getFullPathNoEndSeparator(allIndexFiles.get(0));
                File dataFilesDir = new File(Paths.get(filePath, "_TSV Exports").toString());
                if (dataFilesDir.exists()) {
                    currentCase.addReport(allIndexFiles.get(0), MODULE_NAME, Bundle.CLeappAnalyzerIngestModule_report_name());
                }
            }

        } catch (IOException | UncheckedIOException | TskCoreException ex) {
            // catch the error and continue on as report is not added
            logger.log(Level.WARNING, String.format("Error finding index file in path %s", cLeappOutputDir.toString()), ex);
        }

    }

    /*
     * Reads the cLeapp paths file to get the paths that we want to extract
     *
     */
    private List<String> loadCleappPathFile(Path moduleOutputPath) throws FileNotFoundException, IOException {
        List<String> cLeappPathsToProcess = new ArrayList<>();

        Path filePath = Paths.get(moduleOutputPath.toString(), CLEAPP_PATHS_FILE);

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath.toString()))) {
            String line = reader.readLine();
            while (line != null) {
                if (line.contains("path list generation") || line.length() < 2) {
                    line = reader.readLine();
                    continue;
                }
                cLeappPathsToProcess.add(line.trim());
                line = reader.readLine();
            }
        }

        return cLeappPathsToProcess;
    }

    private void extractFilesFromImage(Content dataSource, List<String> cLeappPathsToProcess, Path moduleOutputPath) {
        FileManager fileManager = getCurrentCase().getServices().getFileManager();

        for (String fullFilePath : cLeappPathsToProcess) {

            if (context.dataSourceIngestIsCancelled()) {
                logger.log(Level.INFO, "cLeapp Analyser ingest module run was canceled"); //NON-NLS
                break;
            }

            String ffp = fullFilePath.replaceAll("\\*", "%");
            ffp = FilenameUtils.normalize(ffp, true);
            String fileName = FilenameUtils.getName(ffp);
            String filePath = FilenameUtils.getPath(ffp);

            List<AbstractFile> cLeappFiles = new ArrayList<>();
            try {
                if (filePath.isEmpty()) {
                    cLeappFiles = fileManager.findFiles(dataSource, fileName); //NON-NLS                
                } else {
                    cLeappFiles = fileManager.findFiles(dataSource, fileName, filePath); //NON-NLS
                }
            } catch (TskCoreException ex) {
                logger.log(Level.WARNING, "No files found to process"); //NON-NLS
                return;
            }

            for (AbstractFile cLeappFile : cLeappFiles) {
                Path parentPath = Paths.get(moduleOutputPath.toString(), cLeappFile.getParentPath());
                File fileParentPath = new File(parentPath.toString());

                extractFileToOutput(dataSource, cLeappFile, fileParentPath, parentPath);
            }
        }
    }

    private void extractFileToOutput(Content dataSource, AbstractFile cLeappFile, File fileParentPath, Path parentPath) {
        if (fileParentPath.exists()) {
                    if (!cLeappFile.isDir()) {
                        writecLeappFile(dataSource, cLeappFile, fileParentPath.toString());
                    } else {
                        try {
                            Files.createDirectories(Paths.get(parentPath.toString(), cLeappFile.getName()));
                        } catch (IOException ex) {
                            logger.log(Level.INFO, String.format("Error creating cLeapp output directory %s", parentPath.toString()), ex);
                        }
                    }
                } else {
                    try {
                        Files.createDirectories(parentPath);
                    } catch (IOException ex) {
                        logger.log(Level.INFO, String.format("Error creating cLeapp output directory %s", parentPath.toString()), ex);
                    }
                    if (!cLeappFile.isDir()) {
                        writecLeappFile(dataSource, cLeappFile, fileParentPath.toString());
                    } else {
                        try {
                            Files.createDirectories(Paths.get(parentPath.toString(), cLeappFile.getName()));
                        } catch (IOException ex) {
                            logger.log(Level.INFO, String.format("Error creating cLeapp output directory %s", parentPath.toString()), ex);
                        }
                    }
                }
    }
    
    private void writecLeappFile(Content dataSource, AbstractFile cLeappFile, String parentPath) {
        String fileName = cLeappFile.getName().replace(":", "-");
        if (!fileName.matches(".") && !fileName.matches("..") && !fileName.toLowerCase().endsWith("-slack")) {
            Path filePath = Paths.get(parentPath, fileName);
            File localFile = new File(filePath.toString());
            try {
                ContentUtils.writeToFile(cLeappFile, localFile, context::dataSourceIngestIsCancelled);
            } catch (ReadContentInputStream.ReadContentInputStreamException ex) {
                logger.log(Level.WARNING, String.format("Error reading file '%s' (id=%d).",
                        cLeappFile.getName(), cLeappFile.getId()), ex); //NON-NLS
            } catch (IOException ex) {
                logger.log(Level.WARNING, String.format("Error writing file local file '%s' (id=%d).",
                        filePath.toString(), cLeappFile.getId()), ex); //NON-NLS
            }
        }
    }
}
