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
package org.sleuthkit.autopsy.modules.chainsaw;

import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvParser;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import static java.util.Locale.US;
import java.util.Map;
import java.util.logging.Level;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.openide.modules.InstalledFileLocator;
import org.openide.util.Exceptions;
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
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.ReadContentInputStream;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskException;

/**
 * Data source ingest module that runs cLeapp against logical iOS files.
 */
public class ChainsawIngestModule implements DataSourceIngestModule {

    private static final Logger logger = Logger.getLogger(ChainsawIngestModule.class.getName());
    private static final String MODULE_NAME = ChainsawModuleFactory.getModuleName();

    private static final String CHAINSAW = "chainsaw"; //NON-NLS
    private static final String CHAINSAW_EXECUTABLE = "chainsaw.exe";//NON-NLS
    private static final String BASE_DIR_NAME = "modules";
    private static final String DATASOURCE = "datasource"; //NON-NLS
    
    private final Map<String, BlackboardAttribute.Type> columnAttributes;
    private static final DateFormat TIMESTAMP_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", US);
    
    Blackboard blkBoard;
    
    private File chainsawExecutable;
    private String executableFilePath;

    private IngestJobContext context;

    ChainsawIngestModule() {
        this.columnAttributes = new HashMap<>();     
    }

    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        this.context = context;

        if (false == PlatformUtil.is64BitOS()) {
            throw new IngestModuleException(NbBundle.getMessage(this.getClass(), "ChainsawIngestModule.not.64.bit.os"));
        }

        if (false == PlatformUtil.isWindowsOS()) {
            throw new IngestModuleException(NbBundle.getMessage(this.getClass(), "ChainsawIngestModule_requires_windows"));
        }

        try {
            chainsawExecutable = locateExecutable(CHAINSAW_EXECUTABLE);
            executableFilePath = org.apache.commons.io.FilenameUtils.getFullPath(chainsawExecutable.toString());
            
        } catch (FileNotFoundException exception) {
            logger.log(Level.WARNING, "chainsaw executable not found.", exception); //NON-NLS
            throw new IngestModuleException(NbBundle.getMessage(this.getClass(), "ChainsawIngestModule_executable_not_found"), exception);
        }

    }

    @NbBundle.Messages({
        "ChainsawIngestModule.error.running.chainsaw=Error running chainsaw, see log file.",
        "ChainsawIngestModule.error.creating.output.dir=Error creating chainsaw module output directory.",
        "ChainsawIngestModule.starting.chainsaw=Starting chainsaw",
        "ChainsawIngestModule.running.chainsaw=Running chainsaw",
        "ChainsawIngestModule.has.run=Chainsaw",
        "ChainsawIngestModule.chainsaw.cancelled=chainsaw run was canceled",
        "ChainsawIngestModule.completed=chainsaw Processing Completed",
        "ChainsawIngestModule.report.name=chainsaw Html Report",
        "ChainsawFileProcessor.postartifacts_error=Error posting Blackboard Artifact",})
    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress statusHelper) {

        Case currentCase = Case.getCurrentCase();
        Path tempOutputPath = Paths.get(currentCase.getTempDirectory(), CHAINSAW, "DataSource" + dataSource.getId());
        try {
            Files.createDirectories(tempOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating chainsaw temp directory %s", tempOutputPath.toString()), ex);
            return ProcessResult.ERROR;
        }

        statusHelper.progress(Bundle.ChainsawIngestModule_starting_chainsaw(), 0);

        extractFilesFromImage(dataSource, tempOutputPath.toString());

        try {
            processChainsaw(dataSource, currentCase, statusHelper, tempOutputPath);
        } catch (NoCurrentCaseException ex) {
            return ProcessResult.ERROR;
        }

        IngestMessage message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                Bundle.ChainsawIngestModule_has_run(),
                Bundle.ChainsawIngestModule_completed());
        IngestServices.getInstance().postMessage(message);
        return ProcessResult.OK;
    }

    /**
     * Process a file from a logical image using the cLeapp program
     * @param dataSource datasource to process
     * @param currentCase current case that is being worked on
     * @param statusHelper show progress and update what is being processed
     * @param tempOutputPath path where the event logs are written to
     */
    private void processChainsaw(Content dataSource, Case currentCase, DataSourceIngestModuleProgress statusHelper, Path tempOutputPath) throws NoCurrentCaseException{
        String currentTime = new SimpleDateFormat("yyyy-MM-dd HH-mm-ss z", Locale.US).format(System.currentTimeMillis());//NON-NLS
        Path moduleOutputPath = Paths.get(currentCase.getModuleDirectory(), CHAINSAW, currentTime);
        try {
            Files.createDirectories(moduleOutputPath);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Error creating chainsaw output directory %s", moduleOutputPath.toString()), ex);
            return;
        }

        statusHelper.progress(NbBundle.getMessage(this.getClass(), "ChainsawIngestModule.processing"));
        ProcessBuilder chainsawCommand = buildChainsawHuntCommand(moduleOutputPath, tempOutputPath.toString());
        try {
            int result = ExecUtil.execute(chainsawCommand, new DataSourceIngestModuleProcessTerminator(context, true));
            if (result != 0) {
                logger.log(Level.WARNING, String.format("Error when trying to execute chainsaw program result is %d", result));
                return;
            }

        } catch (IOException ex) {
            logger.log(Level.SEVERE, "Error when trying to execute chainsaw program", ex);
            return;
        }

        if (context.dataSourceIngestIsCancelled()) {
            logger.log(Level.INFO, "Chainsaw Analyser ingest module run was canceled"); //NON-NLS
            return;
        }
        
        List<String> allCsvFiles = new ArrayList<>();
                
        try {
            allCsvFiles = findCsvFiles(moduleOutputPath);
        } catch (IngestModuleException ex) {
            logger.log(Level.SEVERE, String.format("Error finding CSV files in  output directory %s", moduleOutputPath.toString()), ex);
        }
        
        blkBoard = Case.getCurrentCaseThrows().getSleuthkitCase().getBlackboard();
        processChainsawCSVFiles(allCsvFiles, dataSource);

    }

    /** 
     * 
     * Process the chainsaw csv files that are found in the module output directory
     *  @param csvFiles - List of csv files that are to be processed
     *  @param dataSource datasource to process
     *
     **/
    private void processChainsawCSVFiles(List<String> csvFiles, Content dataSource) {
        List<BlackboardArtifact> bbartifacts = new ArrayList<>();
        
        for (String csvFileName : csvFiles) {
            File csvFile = new File(csvFileName);
                String baseFileName = org.apache.commons.io.FilenameUtils.getBaseName(csvFile.toString().toUpperCase());
                String baseFileNameDesc = baseFileName.replaceAll("_", " ");
                try {
                    BlackboardArtifact.Type artifactType = Case.getCurrentCase().getSleuthkitCase().getBlackboard().getOrAddArtifactType("CS_" + baseFileName, baseFileNameDesc); 
                    processFile(csvFile, artifactType, bbartifacts, dataSource);
                } catch (BlackboardException ex) {
                    logger.log(Level.WARNING, String.format("Error creating Artifact %s", csvFile.toString()), ex);         
                } catch (IOException ex) {
                    logger.log(Level.WARNING, String.format("Error reading file %s", csvFile.toString()), ex);         
            } catch (IngestModuleException ex) {
                Exceptions.printStackTrace(ex);
            }
        }
        
        if (!bbartifacts.isEmpty()) {
            postArtifacts(bbartifacts);
        }

    }
    
    /**
     * Read each Csv file and process it to create an artifact and attributes for it.
     * @param csvFile the csv file to process
     * @param artifactType the blackboard artifact that the csv file identifies as
     * @param bbartifacts list of bbartifacts to add to
     * @param dataSource the current datasource that you are running u=ingest from
     **/ 
     
     private void processFile(File csvFile, BlackboardArtifact.Type artifactType,
            List<BlackboardArtifact> bbartifacts, Content dataSource) throws FileNotFoundException, IOException, IngestModuleException {

        // based on https://stackoverflow.com/questions/56921465/jackson-csv-schema-for-array
        try (MappingIterator<List<String>> iterator = new CsvMapper()
                .enable(CsvParser.Feature.WRAP_AS_ARRAY)
                .readerFor(List.class)
                .with(CsvSchema.emptySchema().withColumnSeparator(','))
                .readValues(csvFile)) {

            if (iterator.hasNext()) {
                List<String> headerItems = iterator.next();
                Map<Integer, String> columnIndexes = IntStream.range(0, headerItems.size())
                        .mapToObj(idx -> idx)
                        .collect(Collectors.toMap(
                                idx -> idx,
                                idx -> headerItems.get(idx) == null ? null : headerItems.get(idx).trim().toLowerCase(),
                                (val2, val1) -> val1));
                createOrGetColumnAttributes(headerItems);
                int lineNum = 2;
                while (iterator.hasNext()) {
                    List<String> columnItems = iterator.next();
                    Collection<BlackboardAttribute> bbattributes = processReadLine(columnItems, columnIndexes, csvFile.toString(), lineNum);
                    BlackboardArtifact bbartifact = createArtifactWithAttributes(artifactType.getTypeID(), dataSource, bbattributes);
                    if (bbartifact != null) {
                        bbartifacts.add(bbartifact);
                    }
                    lineNum++;
                }
            }
        }
    }

    /**
     * create or get column attributes based on the header row of the csv file
     * @param headerItems header row of the csv file
     */
     private void createOrGetColumnAttributes(List<String> headerItems) {
        
        for (String header : headerItems) {
                BlackboardAttribute.Type foundAttrType = null;
                try {
                    foundAttrType = Case.getCurrentCase().getSleuthkitCase().getAttributeType("CS_" + header.toUpperCase());
                } catch (TskCoreException ex) {
                    logger.log(Level.SEVERE, String.format("There was an issue that arose while trying to fetch attribute type for %s.", header), ex);
                }

                if (foundAttrType == null) {
                   try {
                       if (header.toUpperCase().contains("SYSTEM_TIME")) {
                           foundAttrType = blkBoard.getOrAddAttributeType("CS_" + header.toUpperCase(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, header.replaceAll("_", " "));
                       } else if (header.toUpperCase().equals("ID")) {
                           foundAttrType = blkBoard.getOrAddAttributeType("CS_" + header.toUpperCase(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, header.replaceAll("_", " "));
                       } else {
                           foundAttrType = blkBoard.getOrAddAttributeType("CS_" + header.toUpperCase(), BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, header.replaceAll("_", " "));
                       }
                   } catch (Blackboard.BlackboardException ex) {
                       logger.log(Level.WARNING, String.format("Failed to create custom attribute type %s.", "CS_" + header.toUpperCase()), ex);
                   }
                }
                
                columnAttributes.put(header.toUpperCase(), foundAttrType);
        }
    }

    /**
     * Process the line read and create the necessary attributes for it.
     *
     * @param lineValues List of column values.
     * @param columnIndexes Mapping of column headers (trimmed; to lower case)
     * to column index. All header columns and only all header columns should be
     * present.
     * @param fileName The name of the file being processed.
     * @param lineNum The line number in the file.
     * @return The collection of blackboard attributes for the artifact created
     * from this line.
     * @throws IngestModuleException
     */
    private Collection<BlackboardAttribute> processReadLine(List<String> lineValues, Map<Integer, String> columnIndexes,
            String fileName, int lineNum) throws IngestModuleException {
        List<BlackboardAttribute> attrsToRet = new ArrayList<>();
        if (MapUtils.isEmpty(columnIndexes) || CollectionUtils.isEmpty(lineValues)
                || (lineValues.size() == 1 && StringUtils.isEmpty(lineValues.get(0)))) {
            return Collections.emptyList();
        } else if (lineValues.size() != columnIndexes.size()) {
            logger.log(Level.WARNING, String.format(
                    "Row at line number %d in file %s has %d columns when %d were expected based on the header row.",
                    lineNum, fileName, lineValues.size(), columnIndexes.size()));
            return Collections.emptyList();
        }
        
        for (int i = 0; i < lineValues.size(); i++) {
            String columnName = columnIndexes.get(i);
            BlackboardAttribute attr = null;
            logger.log(Level.WARNING, String.format("Column Name %s and lineValue %s and forloop %d", columnName, lineValues.get(i), i));
            if (columnName.toUpperCase().contains("SYSTEM_TIME")) {
                try {
                    Long dateTime = TIMESTAMP_FORMAT.parse(lineValues.get(i)).getTime() / 1000;
                    attr = (lineValues.get(i) == null) ? null : new BlackboardAttribute(columnAttributes.get(columnName.toUpperCase()), MODULE_NAME, dateTime);
                } catch (ParseException ex) {
                    logger.log(Level.WARNING, String.format("Error parsing date %s", lineValues.get(i)), ex);
                }
            } else if (columnName.toUpperCase().equals("ID")) {
                attr = (lineValues.get(i) == null) ? null : new BlackboardAttribute(columnAttributes.get(columnName.toUpperCase()), MODULE_NAME, Integer.valueOf(lineValues.get(i)));
            } else {
                attr = (lineValues.get(i) == null) ? null : new BlackboardAttribute(columnAttributes.get(columnName.toUpperCase()), MODULE_NAME, lineValues.get(i));
            }
//            BlackboardAttribute attr = (lineValues.get(i) == null) ? null : new BlackboardAttribute(columnAttributes.get(columnName.toUpperCase()), MODULE_NAME, lineValues.get(i));
            if (attr == null) {
                logger.log(Level.WARNING, String.format("Blackboard attribute could not be parsed column %s at line %d in file %s.  Omitting row.", columnName, i, fileName));
                return Collections.emptyList();
            }
            attrsToRet.add(attr);
            
        }
        
        return attrsToRet;
    }
    
    /**
     * Generic method for creating a blackboard artifact with attributes
     *
     * @param type is a blackboard.artifact_type enum to determine which type
     * the artifact should be
     * @param dataSource is the Content object that needs to have the artifact
     * added for it
     * @param bbattributes is the collection of blackboard attributes that need
     * to be added to the artifact after the artifact has been created
     *
     * @return The newly-created artifact, or null on error
     */
    private BlackboardArtifact createArtifactWithAttributes(int type, Content dataSource, Collection<BlackboardAttribute> bbattributes) {
        try {
            BlackboardArtifact bbart = dataSource.newArtifact(type);
            bbart.addAttributes(bbattributes);
            return bbart;
        } catch (TskException ex) {
            logger.log(Level.WARNING, "Chainsaw Error creating artifacts with attributes", ex); //NON-NLS
        }
        return null;
    }

    /**
     * Build the command to run the Chainsaw executable
     * @param moduleOutputPath the output path where to write the csv files to
     * @param tempOutputPath the input path where the event logs to process are
     * @return processbuilder 
     */
    private ProcessBuilder buildChainsawHuntCommand(Path moduleOutputPath, String tempOutputPath) {

        ProcessBuilder processBuilder = buildProcessWithRunAsInvoker(
                "\"" + chainsawExecutable + "\"", //NON-NLS
                "hunt", //NON-NLS
                tempOutputPath + "/",
                "--rules",
                executableFilePath + "sigma_rules",
                "--mapping",
                executableFilePath + "mapping_files/sigma-mapping.yml",
                "--csv",
                moduleOutputPath.toString()
        );
        processBuilder.redirectError(moduleOutputPath.resolve("chainsaw_hunt_error.txt").toFile());  //NON-NLS
        processBuilder.redirectOutput(moduleOutputPath.resolve("chainsaw_hunt.txt").toFile());  //NON-NLS
        return processBuilder;
    }

    static private ProcessBuilder buildProcessWithRunAsInvoker(String... commandLine) {
        ProcessBuilder processBuilder = new ProcessBuilder(commandLine);
        /*
         * Add an environment variable to force Chainsaw to run with
         * the same permissions Autopsy uses.
         */
        processBuilder.environment().put("__COMPAT_LAYER", "RunAsInvoker"); //NON-NLS
        return processBuilder;
    }

    /**
     * Search for the location of the executable program
     * @param executableName name of the executable to search for
     * @return returns the location of the executable program
     * @throws FileNotFoundException 
     */
    private static File locateExecutable(String executableName) throws FileNotFoundException {
        String executableToFindName = Paths.get(BASE_DIR_NAME, CHAINSAW, executableName).toString();

        File exeFile = InstalledFileLocator.getDefault().locate(executableToFindName, ChainsawIngestModule.class.getPackage().getName(), false);
        logger.log(Level.INFO, "chainsaw executable found"); //NON-NLS
        if (null == exeFile || exeFile.canExecute() == false) {
            throw new FileNotFoundException(executableName + " executable not found.");
        }
        return exeFile;
    }

    @NbBundle.Messages({"ChainsawFileProcessor.error.reading.chainsaw.directory=Error reading Chainsaw Output Directory"})
    /**
     * Find the csv files in the chainsaw output directory and match them to files
     * we know we want to process and return the list to process those files.
     * @param moduleOutputDir the directory where the csv files live
     * @return a list of the csv files that live in the moduleOutputDir
     * @throws FileNotFoundException
     */
    private List<String> findCsvFiles(Path moduleOutputDir) throws IngestModuleException {
        List<String> allCsvFiles = new ArrayList<>();

        try (Stream<Path> walk = Files.walk(moduleOutputDir)) {

            allCsvFiles = walk.map(x -> x.toString())
                    .filter(f -> f.toLowerCase().endsWith(".csv")).collect(Collectors.toList());

        } catch (IOException | UncheckedIOException e) {
            throw new IngestModuleException(Bundle.ChainsawFileProcessor_error_reading_chainsaw_directory() + moduleOutputDir.toString(), e);
        }

        return allCsvFiles;

    }
    
    /**
     * 
     * @param dataSource datasource to extract the evtx files from 
     * @param moduleOutputPath output path to write the evtx files to
     */
    private void extractFilesFromImage(Content dataSource, String moduleOutputPath) {
        FileManager fileManager = getCurrentCase().getServices().getFileManager();

        if (context.dataSourceIngestIsCancelled()) {
            logger.log(Level.INFO, "chainsaw Analyser ingest module run was canceled"); //NON-NLS
            return;
        }

        List<AbstractFile> evtxFiles = new ArrayList<>();
        try {
            evtxFiles = fileManager.findFiles(dataSource, "%.evtx"); //NON-NLS                
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, "No files found to process"); //NON-NLS
            return;
        }

        for (AbstractFile evtxFile : evtxFiles) {
            writeEvtxFile(dataSource, evtxFile, moduleOutputPath);
        }
        
    }

    /**
     * 
     * @param dataSource datasource to pull the evtx file from 
     * @param evtxFile the evtf file to extract
     * @param moduleOutputPath the output path to write the evtx file to
     */
    private void writeEvtxFile(Content dataSource, AbstractFile evtxFile, String moduleOutputPath) {
        String fileName = evtxFile.getName().replace(":", "-");
        if (!fileName.matches(".") && !fileName.matches("..") && !fileName.toLowerCase().endsWith("-slack")) {
            Path filePath = Paths.get(moduleOutputPath, fileName);
            File localFile = new File(filePath.toString());
            try {
                ContentUtils.writeToFile(evtxFile, localFile, context::dataSourceIngestIsCancelled);
            } catch (ReadContentInputStream.ReadContentInputStreamException ex) {
                logger.log(Level.WARNING, String.format("Error reading file '%s' (id=%d).",
                        evtxFile.getName(), evtxFile.getId()), ex); //NON-NLS
            } catch (IOException ex) {
                logger.log(Level.WARNING, String.format("Error writing file local file '%s' (id=%d).",
                        filePath.toString(), evtxFile.getId()), ex); //NON-NLS
            }
        }
    }

    /**
     * Method to post a list of BlackboardArtifacts to the blackboard.
     *
     * @param artifacts A list of artifacts. IF list is empty or null, the
     * function will return.
     */
    void postArtifacts(Collection<BlackboardArtifact> artifacts) {
        if (artifacts == null || artifacts.isEmpty()) {
            return;
        }

        try {
            Case.getCurrentCase().getSleuthkitCase().getBlackboard().postArtifacts(artifacts, MODULE_NAME);
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, Bundle.ChainsawFileProcessor_postartifacts_error(), ex); //NON-NLS
        }
    }

}
