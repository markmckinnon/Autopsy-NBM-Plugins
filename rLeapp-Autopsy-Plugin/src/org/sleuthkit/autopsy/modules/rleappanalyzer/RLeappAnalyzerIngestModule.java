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
package org.sleuthkit.autopsy.modules.rleappanalyzer;

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
import org.sleuthkit.autopsy.modules.rleappanalyzer.Bundle;
import org.sleuthkit.autopsy.modules.rleappanalyzer.Bundle;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.LocalFilesDataSource;
import org.sleuthkit.datamodel.ReadContentInputStream;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Data source ingest module that runs rLeapp against logical iOS files.
 */
public class RLeappAnalyzerIngestModule implements DataSourceIngestModule {

    private static final Logger logger = Logger.getLogger(RLeappAnalyzerIngestModule.class.getName());
    private static final String MODULE_NAME = RLeappAnalyzerModuleFactory.getModuleName();

    private static final String RLEAPP = "rLeapp"; //NON-NLS
    private static final String RLEAPP_FS = "fs"; //NON-NLS
    private static final String RLEAPP_EXECUTABLE = "rLeapp.exe";//NON-NLS
    private static final String RLEAPP_PATHS_FILE = "rLeapp_paths.txt"; //NON-NLS
    private static final String BASE_DIR_NAME = "modules";
    
    private static final String XMLFILE = "rleap-artifact-attribute-reference.xml"; //NON-NLS


    private File rLeappExecutable;

    private IngestJobContext context;

    private LeappFileProcessor rLeappFileProcessor;

    RLeappAnalyzerIngestModule() {
        // This constructor is intentionally empty. Nothing special is needed here.     
    }

    @NbBundle.Messages({
        "RLeappAnalyzerIngestModule.executable.not.found=rLeapp Executable Not Found.",
        "RLeappAnalyzerIngestModule.requires.windows=rLeapp module requires windows.",
        "RLeappAnalyzerIngestModule.error.rleapp.file.processor.init=Failure to initialize rLeappProcessFile"})
    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        this.context = context;

        if (false == PlatformUtil.is64BitOS()) {
            throw new IngestModuleException(NbBundle.getMessage(this.getClass(), "RleappAnalyzerIngestModule.not.64.bit.os"));
        }

        if (false == PlatformUtil.isWindowsOS()) {
            throw new IngestModuleException(Bundle.RLeappAnalyzerIngestModule_requires_windows());
        }

        try {
            rLeappFileProcessor = new LeappFileProcessor(XMLFILE, RLeappAnalyzerModuleFactory.getModuleName());
        } catch (IOException | IngestModuleException | NoCurrentCaseException ex) {
            throw new IngestModuleException(Bundle.RLeappAnalyzerIngestModule_error_rleapp_file_processor_init(), ex);
        }

        try {
            rLeappExecutable = locateExecutable(RLEAPP_EXECUTABLE);
        } catch (FileNotFoundException exception) {
            logger.log(Level.WARNING, "rLeapp executable not found.", exception); //NON-NLS
            throw new IngestModuleException(Bundle.RLeappAnalyzerIngestModule_executable_not_found(), exception);
        }

    }

    @NbBundle.Messages({
        "RLeappAnalyzerIngestModule.error.running.rLeapp=Error running rLeapp, see log file.",
        "RLeappAnalyzerIngestModule.error.creating.output.dir=Error creating rLeapp module output directory.",
        "RLeappAnalyzerIngestModule.starting.rLeapp=Starting rLeapp",
        "RLeappAnalyzerIngestModule.running.rLeapp=Running rLeapp",
        "RLeappAnalyzerIngestModule.has.run=rLeapp",
        "RLeappAnalyzerIngestModule.rLeapp.cancelled=rLeapp run was canceled",
        "RLeappAnalyzerIngestModule.completed=rLeapp Processing Completed",
        "RLeappAnalyzerIngestModule.report.name=rLeapp Html Report"})
    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress statusHelper) {

        Case currentCase = Case.getCurrentCase();
        Path tempOutputPath = Paths.get(currentCase.getTempDirectory(), RLEAPP, RLEAPP_FS + dataSource.getId());
        try {
            Files.createDirectories(tempOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating rLeapp output directory %s", tempOutputPath.toString()), ex);
            return ProcessResult.ERROR;
        }

        List<String> rLeappPathsToProcess = new ArrayList<>();
        ProcessBuilder rLeappCommand = buildrLeappListCommand(tempOutputPath);
        try {
            int result = ExecUtil.execute(rLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.SEVERE, String.format("Error when trying to execute rLeapp program getting file paths to search for result is %d", result));
                return ProcessResult.ERROR;
            }
            rLeappPathsToProcess = loadCleappPathFile(tempOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute rLeapp program getting file paths to search"), ex);
            return ProcessResult.ERROR;
        }

        statusHelper.progress(Bundle.RLeappAnalyzerIngestModule_starting_rLeapp(), 0);

        List<AbstractFile> rLeappFilesToProcess = new ArrayList<>();

        if (context.getDataSource() instanceof LocalFilesDataSource && !(context.getDataSource().getName().contentEquals("QNX6-Image-File")) ) {
            rLeappFilesToProcess = LeappFileProcessor.findLeappFilesToProcess(dataSource);
            statusHelper.switchToDeterminate(rLeappFilesToProcess.size());

            Integer filesProcessedCount = 0;
            for (AbstractFile rLeappFile : rLeappFilesToProcess) {
                processRLeappFile(dataSource, currentCase, statusHelper, filesProcessedCount, rLeappFile);
                filesProcessedCount++;
            }
       } else {
            // Process the logical image as a fs in rLeapp to make sure this is not a logical fs that was added
            extractFilesFromImage(dataSource, rLeappPathsToProcess, tempOutputPath);
            processRLeappFs(dataSource, currentCase, statusHelper, tempOutputPath.toString());
            extractFilesFromImage(dataSource, rLeappPathsToProcess, tempOutputPath);
            statusHelper.switchToDeterminate(rLeappFilesToProcess.size());
            processRLeappFs(dataSource, currentCase, statusHelper, tempOutputPath.toString());
        }
       
        IngestMessage message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                Bundle.RLeappAnalyzerIngestModule_has_run(),
                Bundle.RLeappAnalyzerIngestModule_completed());
        IngestServices.getInstance().postMessage(message);
        return ProcessResult.OK;
    }

    /**
     * Process a file from a logical image using the rLeapp program
     * @param dataSource datasource to process
     * @param currentCase current case that is being worked on
     * @param statusHelper show progress and update what is being processed
     * @param filesProcessedCount number of files that have been processed
     * @param rLeappFile the abstract file to process
     */
    private void processRLeappFile(Content dataSource, Case currentCase, DataSourceIngestModuleProgress statusHelper, int filesProcessedCount,
            AbstractFile rLeappFile) {
        String currentTime = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss z", Locale.US).format(System.currentTimeMillis());//NON-NLS
        Path moduleOutputPath = Paths.get(currentCase.getModuleDirectory(), RLEAPP, currentTime);
        try {
            Files.createDirectories(moduleOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating rLeapp output directory %s", moduleOutputPath.toString()), ex);
            return;
        }

        statusHelper.progress(NbBundle.getMessage(this.getClass(), "RLeappAnalyzerIngestModule.processing.file", rLeappFile.getName()), filesProcessedCount);
        ProcessBuilder rLeappCommand = buildrLeappCommand(moduleOutputPath, rLeappFile.getLocalAbsPath(), rLeappFile.getNameExtension());
        try {
            int result = ExecUtil.execute(rLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.WARNING, String.format("Error when trying to execute rLeapp program getting file paths to search for result is %d", result));
                return;
            }

            addLeappReportToReports(moduleOutputPath, currentCase);

        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute rLeapp program against file %s", rLeappFile.getLocalAbsPath()), ex);
            return;
        }

        if (context.dataSourceIngestIsCancelled()) {
            logger.log(Level.INFO, "rLeapp Analyser ingest module run was canceled"); //NON-NLS
            return;
        }

        ProcessResult fileProcessorResult = rLeappFileProcessor.processFiles(dataSource, moduleOutputPath, rLeappFile);

        if (fileProcessorResult == ProcessResult.ERROR) {
            return;
        }
    }

    /**
     * Process a image/directory using the rLeapp program
     * @param dataSource datasource to process
     * @param currentCase current case being procesed
     * @param statusHelper show progress and update what is being processed
     * @param directoryToProcess directory to run rLeapp against
     */
    private void processRLeappFs(Content dataSource, Case currentCase, DataSourceIngestModuleProgress statusHelper, String directoryToProcess) {
        String currentTime = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss z", Locale.US).format(System.currentTimeMillis());//NON-NLS
        Path moduleOutputPath = Paths.get(currentCase.getModuleDirectory(), RLEAPP, currentTime);
        try {
            Files.createDirectories(moduleOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating rLeapp output directory %s", moduleOutputPath.toString()), ex);
            return;
        }

        statusHelper.progress(NbBundle.getMessage(this.getClass(), "RLeappAnalyzerIngestModule.processing.filesystem"));
        ProcessBuilder rLeappCommand = buildrLeappCommand(moduleOutputPath, directoryToProcess, "fs");
        try {
            int result = ExecUtil.execute(rLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.WARNING, String.format("Error when trying to execute rLeapp program getting file paths to search for result is %d", result));
                return;
            }

            addLeappReportToReports(moduleOutputPath, currentCase);

        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute rLeapp program against file system"), ex);
            return;
        }

        if (context.dataSourceIngestIsCancelled()) {
            logger.log(Level.INFO, "rLeapp Analyser ingest module run was canceled"); //NON-NLS
            return;
        }

        ProcessResult fileProcessorResult = rLeappFileProcessor.processFileSystem(dataSource, moduleOutputPath);

        if (fileProcessorResult == ProcessResult.ERROR) {
            return;
        }

    }



    /**
     * Build the rLeapp command to run
     * 
     * @param moduleOutputPath output path for the rLeapp program.
     * @param sourceFilePath where the source files to process reside.
     * @param rLeappFileSystemType the filesystem type to process
     * 
     * @return the command to execute
     */
    private ProcessBuilder buildrLeappCommand(Path moduleOutputPath, String sourceFilePath, String rLeappFileSystemType) {

        ProcessBuilder processBuilder = buildProcessWithRunAsInvoker(
                "\"" + rLeappExecutable + "\"", //NON-NLS
                "-t", rLeappFileSystemType, //NON-NLS
                "-i", sourceFilePath, //NON-NLS
                "-o", moduleOutputPath.toString(),
                "-w"
        );
        processBuilder.redirectError(moduleOutputPath.resolve("rLeapp_err.txt").toFile());  //NON-NLS
        processBuilder.redirectOutput(moduleOutputPath.resolve("rLeapp_out.txt").toFile());  //NON-NLS
        return processBuilder;
    }

    private ProcessBuilder buildrLeappListCommand(Path moduleOutputPath) {

        ProcessBuilder processBuilder = buildProcessWithRunAsInvoker(
                "\"" + rLeappExecutable + "\"", //NON-NLS
                "-p"
        );
        processBuilder.redirectError(moduleOutputPath.resolve("rLeapp_paths_error.txt").toFile());  //NON-NLS
        processBuilder.redirectOutput(moduleOutputPath.resolve("rLeapp_paths.txt").toFile());  //NON-NLS
        return processBuilder;
    }

    static private ProcessBuilder buildProcessWithRunAsInvoker(String... commandLine) {
        ProcessBuilder processBuilder = new ProcessBuilder(commandLine);
        /*
         * Add an environment variable to force rLeapp to run with
         * the same permissions Autopsy uses.
         */
        processBuilder.environment().put("__COMPAT_LAYER", "RunAsInvoker"); //NON-NLS
        return processBuilder;
    }

    private static File locateExecutable(String executableName) throws FileNotFoundException {
        String executableToFindName = Paths.get(BASE_DIR_NAME, RLEAPP, executableName).toString();

        File exeFile = InstalledFileLocator.getDefault().locate(executableToFindName, RLeappAnalyzerIngestModule.class.getPackage().getName(), false);
        if (null == exeFile || exeFile.canExecute() == false) {
            throw new FileNotFoundException(executableName + " executable not found.");
        }
        return exeFile;
    }

    /**
     * Find the index.html file in the rLeapp output directory so it can be
     * added to reports
     */
    private void addLeappReportToReports(Path rLeappOutputDir, Case currentCase) {
        List<String> allIndexFiles = new ArrayList<>();

        try (Stream<Path> walk = Files.walk(rLeappOutputDir)) { 

            allIndexFiles = walk.map(x -> x.toString())
                    .filter(f -> f.toLowerCase().endsWith("index.html")).collect(Collectors.toList());

            if (!allIndexFiles.isEmpty()) {
                // Check for existance of directory that holds report data if does not exist then report contains no data
                String filePath = FilenameUtils.getFullPathNoEndSeparator(allIndexFiles.get(0));
                File dataFilesDir = new File(Paths.get(filePath, "_TSV Exports").toString());
                if (dataFilesDir.exists()) {
                    currentCase.addReport(allIndexFiles.get(0), MODULE_NAME, Bundle.RLeappAnalyzerIngestModule_report_name());
                }
            }

        } catch (IOException | UncheckedIOException | TskCoreException ex) {
            // catch the error and continue on as report is not added
            logger.log(Level.WARNING, String.format("Error finding index file in path %s", rLeappOutputDir.toString()), ex);
        }

    }

    /*
     * Reads the rLeapp paths file to get the paths that we want to extract
     *
     */
    private List<String> loadCleappPathFile(Path moduleOutputPath) throws FileNotFoundException, IOException {
        List<String> rLeappPathsToProcess = new ArrayList<>();

        Path filePath = Paths.get(moduleOutputPath.toString(), RLEAPP_PATHS_FILE);

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath.toString()))) {
            String line = reader.readLine();
            while (line != null) {
                if (line.contains("path list generation") || line.length() < 2) {
                    line = reader.readLine();
                    continue;
                }
                rLeappPathsToProcess.add(line.trim());
                line = reader.readLine();
            }
        }

        return rLeappPathsToProcess;
    }

    private void extractFilesFromImage(Content dataSource, List<String> rLeappPathsToProcess, Path moduleOutputPath) {
        FileManager fileManager = getCurrentCase().getServices().getFileManager();

        for (String fullFilePath : rLeappPathsToProcess) {

            if (context.dataSourceIngestIsCancelled()) {
                logger.log(Level.INFO, "rLeapp Analyser ingest module run was canceled"); //NON-NLS
                break;
            }

            String ffp = fullFilePath.replaceAll("\\*", "%");
            ffp = FilenameUtils.normalize(ffp, true);
            String fileName = FilenameUtils.getName(ffp);
            String filePath = FilenameUtils.getPath(ffp);

            List<AbstractFile> rLeappFiles = new ArrayList<>();
            try {
                if (filePath.isEmpty()) {
                    rLeappFiles = fileManager.findFiles(dataSource, fileName); //NON-NLS                
                } else {
                    rLeappFiles = fileManager.findFiles(dataSource, fileName, filePath); //NON-NLS
                }
            } catch (TskCoreException ex) {
                logger.log(Level.WARNING, "No files found to process"); //NON-NLS
                return;
            }

            for (AbstractFile rLeappFile : rLeappFiles) {
                Path parentPath = Paths.get(moduleOutputPath.toString(), rLeappFile.getParentPath());
                File fileParentPath = new File(parentPath.toString());

                extractFileToOutput(dataSource, rLeappFile, fileParentPath, parentPath);
            }
        }
    }

    private void extractFileToOutput(Content dataSource, AbstractFile rLeappFile, File fileParentPath, Path parentPath) {
        if (fileParentPath.exists()) {
                    if (!rLeappFile.isDir()) {
                        writerLeappFile(dataSource, rLeappFile, fileParentPath.toString());
                    } else {
                        try {
                            Files.createDirectories(Paths.get(parentPath.toString(), rLeappFile.getName()));
                        } catch (IOException ex) {
                            logger.log(Level.INFO, String.format("Error creating rLeapp output directory %s", parentPath.toString()), ex);
                        }
                    }
                } else {
                    try {
                        Files.createDirectories(parentPath);
                    } catch (IOException ex) {
                        logger.log(Level.INFO, String.format("Error creating rLeapp output directory %s", parentPath.toString()), ex);
                    }
                    if (!rLeappFile.isDir()) {
                        writerLeappFile(dataSource, rLeappFile, fileParentPath.toString());
                    } else {
                        try {
                            Files.createDirectories(Paths.get(parentPath.toString(), rLeappFile.getName()));
                        } catch (IOException ex) {
                            logger.log(Level.INFO, String.format("Error creating rLeapp output directory %s", parentPath.toString()), ex);
                        }
                    }
                }
    }
    
    private void writerLeappFile(Content dataSource, AbstractFile rLeappFile, String parentPath) {
        String fileName = rLeappFile.getName().replace(":", "-");
        if (!fileName.matches(".") && !fileName.matches("..") && !fileName.toLowerCase().endsWith("-slack")) {
            Path filePath = Paths.get(parentPath, fileName);
            File localFile = new File(filePath.toString());
            try {
                ContentUtils.writeToFile(rLeappFile, localFile, context::dataSourceIngestIsCancelled);
            } catch (ReadContentInputStream.ReadContentInputStreamException ex) {
                logger.log(Level.WARNING, String.format("Error reading file '%s' (id=%d).",
                        rLeappFile.getName(), rLeappFile.getId()), ex); //NON-NLS
            } catch (IOException ex) {
                logger.log(Level.WARNING, String.format("Error writing file local file '%s' (id=%d).",
                        filePath.toString(), rLeappFile.getId()), ex); //NON-NLS
            }
        }
    }
}
