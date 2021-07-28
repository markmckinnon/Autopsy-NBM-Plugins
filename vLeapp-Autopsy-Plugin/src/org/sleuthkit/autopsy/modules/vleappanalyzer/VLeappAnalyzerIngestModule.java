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
package org.sleuthkit.autopsy.modules.vleappanalyzer;

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
import org.sleuthkit.autopsy.modules.vleappanalyzer.Bundle;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.LocalFilesDataSource;
import org.sleuthkit.datamodel.ReadContentInputStream;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Data source ingest module that runs vLeapp against logical iOS files.
 */
public class VLeappAnalyzerIngestModule implements DataSourceIngestModule {

    private static final Logger logger = Logger.getLogger(VLeappAnalyzerIngestModule.class.getName());
    private static final String MODULE_NAME = VLeappAnalyzerModuleFactory.getModuleName();

    private static final String VLEAPP = "vLeapp"; //NON-NLS
    private static final String VLEAPP_FS = "fs"; //NON-NLS
    private static final String VLEAPP_EXECUTABLE = "vLeapp.exe";//NON-NLS
    private static final String VLEAPP_PATHS_FILE = "vLeapp_paths.txt"; //NON-NLS
    private static final String BASE_DIR_NAME = "modules";
    
    private static final String XMLFILE = "vleap-artifact-attribute-reference.xml"; //NON-NLS


    private File vLeappExecutable;

    private IngestJobContext context;

    private LeappFileProcessor vLeappFileProcessor;

    VLeappAnalyzerIngestModule() {
        // This constructor is intentionally empty. Nothing special is needed here.     
    }

    @NbBundle.Messages({
        "VLeappAnalyzerIngestModule.executable.not.found=vLeapp Executable Not Found.",
        "VLeappAnalyzerIngestModule.requires.windows=vLeapp module requires windows.",
        "VLeappAnalyzerIngestModule.error.vleapp.file.processor.init=Failure to initialize vLeappProcessFile"})
    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        this.context = context;

        if (false == PlatformUtil.is64BitOS()) {
            throw new IngestModuleException(NbBundle.getMessage(this.getClass(), "VleappAnalyzerIngestModule.not.64.bit.os"));
        }

        if (false == PlatformUtil.isWindowsOS()) {
            throw new IngestModuleException(Bundle.VLeappAnalyzerIngestModule_requires_windows());
        }

        try {
            vLeappFileProcessor = new LeappFileProcessor(XMLFILE, VLeappAnalyzerModuleFactory.getModuleName());
        } catch (IOException | IngestModuleException | NoCurrentCaseException ex) {
            throw new IngestModuleException(Bundle.VLeappAnalyzerIngestModule_error_vleapp_file_processor_init(), ex);
        }

        try {
            vLeappExecutable = locateExecutable(VLEAPP_EXECUTABLE);
        } catch (FileNotFoundException exception) {
            logger.log(Level.WARNING, "vLeapp executable not found.", exception); //NON-NLS
            throw new IngestModuleException(Bundle.VLeappAnalyzerIngestModule_executable_not_found(), exception);
        }

    }

    @NbBundle.Messages({
        "VLeappAnalyzerIngestModule.error.running.vLeapp=Error running vLeapp, see log file.",
        "VLeappAnalyzerIngestModule.error.creating.output.dir=Error creating vLeapp module output directory.",
        "VLeappAnalyzerIngestModule.starting.vLeapp=Starting vLeapp",
        "VLeappAnalyzerIngestModule.running.vLeapp=Running vLeapp",
        "VLeappAnalyzerIngestModule.has.run=vLeapp",
        "VLeappAnalyzerIngestModule.vLeapp.cancelled=vLeapp run was canceled",
        "VLeappAnalyzerIngestModule.completed=vLeapp Processing Completed",
        "VLeappAnalyzerIngestModule.report.name=vLeapp Html Report"})
    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress statusHelper) {

        Case currentCase = Case.getCurrentCase();
        Path tempOutputPath = Paths.get(currentCase.getTempDirectory(), VLEAPP, VLEAPP_FS + dataSource.getId());
        try {
            Files.createDirectories(tempOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating vLeapp output directory %s", tempOutputPath.toString()), ex);
            return ProcessResult.ERROR;
        }

        List<String> vLeappPathsToProcess = new ArrayList<>();
        ProcessBuilder vLeappCommand = buildvLeappListCommand(tempOutputPath);
        try {
            int result = ExecUtil.execute(vLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.SEVERE, String.format("Error when trying to execute vLeapp program getting file paths to search for result is %d", result));
                return ProcessResult.ERROR;
            }
            vLeappPathsToProcess = loadCleappPathFile(tempOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute vLeapp program getting file paths to search"), ex);
            return ProcessResult.ERROR;
        }

        statusHelper.progress(Bundle.VLeappAnalyzerIngestModule_starting_vLeapp(), 0);

        List<AbstractFile> vLeappFilesToProcess = new ArrayList<>();

        if (context.getDataSource() instanceof LocalFilesDataSource && !(context.getDataSource().getName().contentEquals("QNX6-Image-File")) ) {
            vLeappFilesToProcess = LeappFileProcessor.findLeappFilesToProcess(dataSource);
            statusHelper.switchToDeterminate(vLeappFilesToProcess.size());

            Integer filesProcessedCount = 0;
            for (AbstractFile vLeappFile : vLeappFilesToProcess) {
                processVLeappFile(dataSource, currentCase, statusHelper, filesProcessedCount, vLeappFile);
                filesProcessedCount++;
            }
       } else {
            // Process the logical image as a fs in vLeapp to make sure this is not a logical fs that was added
            extractFilesFromImage(dataSource, vLeappPathsToProcess, tempOutputPath);
            processVLeappFs(dataSource, currentCase, statusHelper, tempOutputPath.toString());
            extractFilesFromImage(dataSource, vLeappPathsToProcess, tempOutputPath);
            statusHelper.switchToDeterminate(vLeappFilesToProcess.size());
            processVLeappFs(dataSource, currentCase, statusHelper, tempOutputPath.toString());
        }
       
        IngestMessage message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                Bundle.VLeappAnalyzerIngestModule_has_run(),
                Bundle.VLeappAnalyzerIngestModule_completed());
        IngestServices.getInstance().postMessage(message);
        return ProcessResult.OK;
    }

    /**
     * Process a file from a logical image using the vLeapp program
     * @param dataSource datasource to process
     * @param currentCase current case that is being worked on
     * @param statusHelper show progress and update what is being processed
     * @param filesProcessedCount number of files that have been processed
     * @param vLeappFile the abstract file to process
     */
    private void processVLeappFile(Content dataSource, Case currentCase, DataSourceIngestModuleProgress statusHelper, int filesProcessedCount,
            AbstractFile vLeappFile) {
        String currentTime = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss z", Locale.US).format(System.currentTimeMillis());//NON-NLS
        Path moduleOutputPath = Paths.get(currentCase.getModuleDirectory(), VLEAPP, currentTime);
        try {
            Files.createDirectories(moduleOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating vLeapp output directory %s", moduleOutputPath.toString()), ex);
            return;
        }

        statusHelper.progress(NbBundle.getMessage(this.getClass(), "VLeappAnalyzerIngestModule.processing.file", vLeappFile.getName()), filesProcessedCount);
        ProcessBuilder vLeappCommand = buildvLeappCommand(moduleOutputPath, vLeappFile.getLocalAbsPath(), vLeappFile.getNameExtension());
        try {
            int result = ExecUtil.execute(vLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.WARNING, String.format("Error when trying to execute vLeapp program getting file paths to search for result is %d", result));
                return;
            }

            addLeappReportToReports(moduleOutputPath, currentCase);

        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute vLeapp program against file %s", vLeappFile.getLocalAbsPath()), ex);
            return;
        }

        if (context.dataSourceIngestIsCancelled()) {
            logger.log(Level.INFO, "vLeapp Analyser ingest module run was canceled"); //NON-NLS
            return;
        }

        ProcessResult fileProcessorResult = vLeappFileProcessor.processFiles(dataSource, moduleOutputPath, vLeappFile);

        if (fileProcessorResult == ProcessResult.ERROR) {
            return;
        }
    }

    /**
     * Process a image/directory using the vLeapp program
     * @param dataSource datasource to process
     * @param currentCase current case being procesed
     * @param statusHelper show progress and update what is being processed
     * @param directoryToProcess directory to run vLeapp against
     */
    private void processVLeappFs(Content dataSource, Case currentCase, DataSourceIngestModuleProgress statusHelper, String directoryToProcess) {
        String currentTime = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss z", Locale.US).format(System.currentTimeMillis());//NON-NLS
        Path moduleOutputPath = Paths.get(currentCase.getModuleDirectory(), VLEAPP, currentTime);
        try {
            Files.createDirectories(moduleOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating vLeapp output directory %s", moduleOutputPath.toString()), ex);
            return;
        }

        statusHelper.progress(NbBundle.getMessage(this.getClass(), "VLeappAnalyzerIngestModule.processing.filesystem"));
        ProcessBuilder vLeappCommand = buildvLeappCommand(moduleOutputPath, directoryToProcess, "fs");
        try {
            int result = ExecUtil.execute(vLeappCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.WARNING, String.format("Error when trying to execute vLeapp program getting file paths to search for result is %d", result));
                return;
            }

            addLeappReportToReports(moduleOutputPath, currentCase);

        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error when trying to execute vLeapp program against file system"), ex);
            return;
        }

        if (context.dataSourceIngestIsCancelled()) {
            logger.log(Level.INFO, "vLeapp Analyser ingest module run was canceled"); //NON-NLS
            return;
        }

        ProcessResult fileProcessorResult = vLeappFileProcessor.processFileSystem(dataSource, moduleOutputPath);

        if (fileProcessorResult == ProcessResult.ERROR) {
            return;
        }

    }



    /**
     * Build the vLeapp command to run
     * 
     * @param moduleOutputPath output path for the vLeapp program.
     * @param sourceFilePath where the source files to process reside.
     * @param vLeappFileSystemType the filesystem type to process
     * 
     * @return the command to execute
     */
    private ProcessBuilder buildvLeappCommand(Path moduleOutputPath, String sourceFilePath, String vLeappFileSystemType) {

        ProcessBuilder processBuilder = buildProcessWithRunAsInvoker(
                "\"" + vLeappExecutable + "\"", //NON-NLS
                "-t", vLeappFileSystemType, //NON-NLS
                "-i", sourceFilePath, //NON-NLS
                "-o", moduleOutputPath.toString(),
                "-w"
        );
        processBuilder.redirectError(moduleOutputPath.resolve("vLeapp_err.txt").toFile());  //NON-NLS
        processBuilder.redirectOutput(moduleOutputPath.resolve("vLeapp_out.txt").toFile());  //NON-NLS
        return processBuilder;
    }

    private ProcessBuilder buildvLeappListCommand(Path moduleOutputPath) {

        ProcessBuilder processBuilder = buildProcessWithRunAsInvoker(
                "\"" + vLeappExecutable + "\"", //NON-NLS
                "-p"
        );
        processBuilder.redirectError(moduleOutputPath.resolve("vLeapp_paths_error.txt").toFile());  //NON-NLS
        processBuilder.redirectOutput(moduleOutputPath.resolve("vLeapp_paths.txt").toFile());  //NON-NLS
        return processBuilder;
    }

    static private ProcessBuilder buildProcessWithRunAsInvoker(String... commandLine) {
        ProcessBuilder processBuilder = new ProcessBuilder(commandLine);
        /*
         * Add an environment variable to force vLeapp to run with
         * the same permissions Autopsy uses.
         */
        processBuilder.environment().put("__COMPAT_LAYER", "RunAsInvoker"); //NON-NLS
        return processBuilder;
    }

    private static File locateExecutable(String executableName) throws FileNotFoundException {
        String executableToFindName = Paths.get(BASE_DIR_NAME, VLEAPP, executableName).toString();

        File exeFile = InstalledFileLocator.getDefault().locate(executableToFindName, VLeappAnalyzerIngestModule.class.getPackage().getName(), false);
        if (null == exeFile || exeFile.canExecute() == false) {
            throw new FileNotFoundException(executableName + " executable not found.");
        }
        return exeFile;
    }

    /**
     * Find the index.html file in the vLeapp output directory so it can be
     * added to reports
     */
    private void addLeappReportToReports(Path vLeappOutputDir, Case currentCase) {
        List<String> allIndexFiles = new ArrayList<>();

        try (Stream<Path> walk = Files.walk(vLeappOutputDir)) { 

            allIndexFiles = walk.map(x -> x.toString())
                    .filter(f -> f.toLowerCase().endsWith("index.html")).collect(Collectors.toList());

            if (!allIndexFiles.isEmpty()) {
                // Check for existance of directory that holds report data if does not exist then report contains no data
                String filePath = FilenameUtils.getFullPathNoEndSeparator(allIndexFiles.get(0));
                File dataFilesDir = new File(Paths.get(filePath, "_TSV Exports").toString());
                if (dataFilesDir.exists()) {
                    currentCase.addReport(allIndexFiles.get(0), MODULE_NAME, Bundle.VLeappAnalyzerIngestModule_report_name());
                }
            }

        } catch (IOException | UncheckedIOException | TskCoreException ex) {
            // catch the error and continue on as report is not added
            logger.log(Level.WARNING, String.format("Error finding index file in path %s", vLeappOutputDir.toString()), ex);
        }

    }

    /*
     * Reads the vLeapp paths file to get the paths that we want to extract
     *
     */
    private List<String> loadCleappPathFile(Path moduleOutputPath) throws FileNotFoundException, IOException {
        List<String> vLeappPathsToProcess = new ArrayList<>();

        Path filePath = Paths.get(moduleOutputPath.toString(), VLEAPP_PATHS_FILE);

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath.toString()))) {
            String line = reader.readLine();
            while (line != null) {
                if (line.contains("path list generation") || line.length() < 2) {
                    line = reader.readLine();
                    continue;
                }
                vLeappPathsToProcess.add(line.trim());
                line = reader.readLine();
            }
        }

        return vLeappPathsToProcess;
    }

    private void extractFilesFromImage(Content dataSource, List<String> vLeappPathsToProcess, Path moduleOutputPath) {
        FileManager fileManager = getCurrentCase().getServices().getFileManager();

        for (String fullFilePath : vLeappPathsToProcess) {

            if (context.dataSourceIngestIsCancelled()) {
                logger.log(Level.INFO, "vLeapp Analyser ingest module run was canceled"); //NON-NLS
                break;
            }

            String ffp = fullFilePath.replaceAll("\\*", "%");
            ffp = FilenameUtils.normalize(ffp, true);
            String fileName = FilenameUtils.getName(ffp);
            String filePath = FilenameUtils.getPath(ffp);

            List<AbstractFile> vLeappFiles = new ArrayList<>();
            try {
                if (filePath.isEmpty()) {
                    vLeappFiles = fileManager.findFiles(dataSource, fileName); //NON-NLS                
                } else {
                    vLeappFiles = fileManager.findFiles(dataSource, fileName, filePath); //NON-NLS
                }
            } catch (TskCoreException ex) {
                logger.log(Level.WARNING, "No files found to process"); //NON-NLS
                return;
            }

            for (AbstractFile vLeappFile : vLeappFiles) {
                Path parentPath = Paths.get(moduleOutputPath.toString(), vLeappFile.getParentPath());
                File fileParentPath = new File(parentPath.toString());

                extractFileToOutput(dataSource, vLeappFile, fileParentPath, parentPath);
            }
        }
    }

    private void extractFileToOutput(Content dataSource, AbstractFile vLeappFile, File fileParentPath, Path parentPath) {
        if (fileParentPath.exists()) {
                    if (!vLeappFile.isDir()) {
                        writevLeappFile(dataSource, vLeappFile, fileParentPath.toString());
                    } else {
                        try {
                            Files.createDirectories(Paths.get(parentPath.toString(), vLeappFile.getName()));
                        } catch (IOException ex) {
                            logger.log(Level.INFO, String.format("Error creating vLeapp output directory %s", parentPath.toString()), ex);
                        }
                    }
                } else {
                    try {
                        Files.createDirectories(parentPath);
                    } catch (IOException ex) {
                        logger.log(Level.INFO, String.format("Error creating vLeapp output directory %s", parentPath.toString()), ex);
                    }
                    if (!vLeappFile.isDir()) {
                        writevLeappFile(dataSource, vLeappFile, fileParentPath.toString());
                    } else {
                        try {
                            Files.createDirectories(Paths.get(parentPath.toString(), vLeappFile.getName()));
                        } catch (IOException ex) {
                            logger.log(Level.INFO, String.format("Error creating vLeapp output directory %s", parentPath.toString()), ex);
                        }
                    }
                }
    }
    
    private void writevLeappFile(Content dataSource, AbstractFile vLeappFile, String parentPath) {
        String fileName = vLeappFile.getName().replace(":", "-");
        if (!fileName.matches(".") && !fileName.matches("..") && !fileName.toLowerCase().endsWith("-slack")) {
            Path filePath = Paths.get(parentPath, fileName);
            File localFile = new File(filePath.toString());
            try {
                ContentUtils.writeToFile(vLeappFile, localFile, context::dataSourceIngestIsCancelled);
            } catch (ReadContentInputStream.ReadContentInputStreamException ex) {
                logger.log(Level.WARNING, String.format("Error reading file '%s' (id=%d).",
                        vLeappFile.getName(), vLeappFile.getId()), ex); //NON-NLS
            } catch (IOException ex) {
                logger.log(Level.WARNING, String.format("Error writing file local file '%s' (id=%d).",
                        filePath.toString(), vLeappFile.getId()), ex); //NON-NLS
            }
        }
    }
}
