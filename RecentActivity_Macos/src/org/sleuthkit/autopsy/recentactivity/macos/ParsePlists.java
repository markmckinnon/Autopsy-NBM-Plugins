/*
 *
 * Autopsy Forensic Browser
 *
 * Copyright 2012-2021 Basis Technology Corp.
 *
 * Copyright 2012 42six Solutions.
 *
 * Project Contact/Architect: carrier <at> sleuthkit <dot> org
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
package org.sleuthkit.autopsy.recentactivity.macos;

import xmlwise.Plist;
import com.dd.plist.NSArray;
import com.dd.plist.NSDictionary;
import com.dd.plist.NSNumber;
import com.dd.plist.NSObject;
import com.dd.plist.PropertyListFormatException;
import com.dd.plist.PropertyListParser;
import com.google.common.collect.ImmutableMap;
import org.openide.util.NbBundle;
import org.sleuthkit.autopsy.datamodel.ContentUtils;
import java.util.logging.Level;
import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import static java.util.Locale.US;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.openide.util.NbBundle.Messages;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.TskCoreException;
import org.xml.sax.SAXException;
import xmlwise.XmlParseException;

/**
 * Parse Plists
 */
class ParsePlists extends Extract {

    private final Logger logger = Logger.getLogger(this.getClass().getName());
    private Content dataSource;
    private final IngestJobContext context;
    private final String moduleName;

    private static final Map<String, String> XML_PLISTS_MAP = ImmutableMap.<String, String>builder()
            .put("SystemVersion.plist", "System/Library/CoreServices")
            .put("InstallHistory.plist", "Library/Receipts")
            .build();

    private static final Map<String, String> PROCESS_XML_PLISTS_MAP = ImmutableMap.<String, String>builder()
            .put("SystemVersion.plist", "osInfo")
            .put("InstallHistory.plist", "installedPrograms")
            .build();

    @Messages({"Progress_Message_Plist=Processing pList",
               "ParsePlist.displayName=ParsePlists",
    })

    ParsePlists(IngestJobContext context) {
        super(Bundle.ParsePlist_displayName(), context);
        this.context = context;
        moduleName = NbBundle.getMessage(Chromium.class, "ParsePlists.moduleName");
    }

    @Override
    public void process(Content dataSource, DataSourceIngestModuleProgress progressBar) {
        this.dataSource = dataSource;
        dataFound = false;
        long ingestJobId = context.getJobId();
        
        String tempDirPath = RAImageIngestModule.getRATempPath(Case.getCurrentCase(), "plists", context.getJobId()); //NON-NLS

        for (Map.Entry<String, String> xmlPlists : XML_PLISTS_MAP.entrySet()) {
            String plistName = xmlPlists.getKey();
            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Plist"));
            switch (PROCESS_XML_PLISTS_MAP.get(plistName)) {
                case "osInfo":
                    this.getVersion(xmlPlists.getKey(), xmlPlists.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "installedPrograms":
                    this.getInstalledPrograms(xmlPlists.getKey(), xmlPlists.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                default:
                    logger.log(Level.SEVERE, String.format("No XML Plists named %s to Parse", plistName)); //NON-NLS
                    break;
            }
            

            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Chrome_Bookmarks", plistName));
//            this.getBookmark(browser.getKey(), browser.getValue(), ingestJobId);
            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Chrome_Cookies", plistName));
//            this.getCookie(browser.getKey(), browser.getValue(), ingestJobId);
            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Chrome_Logins", plistName));
//            this.getLogins(browser.getKey(), browser.getValue(), ingestJobId);
            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Chrome_AutoFill", plistName));
//            this.getAutofill(browser.getKey(), browser.getValue(), ingestJobId);
            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Chrome_Downloads", plistName));
//            this.getDownload(browser.getKey(), browser.getValue(), ingestJobId);
            if (context.dataSourceIngestIsCancelled()) {
                return;
            }
        }

        progressBar.progress(Bundle.Progress_Message_Chrome_Cache());
        ChromeCacheExtractor chromeCacheExtractor = new ChromeCacheExtractor(dataSource, context, progressBar);
        chromeCacheExtractor.processCaches();
    }

    @Messages({"Error_Finding_Plist_File_OsVersion=Error Finding SystemVersion.plist",
               "Extract_OsVersion_Write_File=Error Writing SystemVersion.plist",
               "Process_OsVersion_Plist_File=Error processing SystemVersion.plist",
               "Process_Plist_File=Error processing plist",
               "Error_Finding_Plist_File_Installed_Programs=Error Finding InstallHistory.plist",
               "Extract_Installed_Programs_Write_File=Error Writing InstallHistory.plist",
               "Process_Installed_Programs_Plist_File=Error processing InstallHistory.plist",})
    
    /**
     * get Version of OS from plist
     *
     * @param plistFileName   File Name of the plist to parse
     * @param plistFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getVersion(String plistFileName, String plistFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> osVersions;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();

        try {
            osVersions = fileManager.findFiles(dataSource, plistFileName, plistFileLocation); //NON-NLS            
        } catch (TskCoreException ex) {
            this.addErrorMessage(NbBundle.getMessage(this.getClass(), "Progress_Message_Plist"));
            logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Progress_Message_Plist"), ex); //NON-NLS
            return;  // No need to continue
        }
        
        for (AbstractFile osVersion : osVersions) {

            String osVersionFileName = tempDirPath + File.separator + osVersion.getId() + "_" + osVersion.getName();

            try {
                ContentUtils.writeToFile(osVersion, new File(osVersionFileName));
            } catch (IOException ex) {
                this.addErrorMessage(NbBundle.getMessage(this.getClass(), "Extract_OsVersion_Write_File"));
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Extract_OsVersion_Write_File"), ex); //NON-NLS
                return;
            }
           
            try {
                File file = new File(osVersionFileName);
                NSDictionary rootDict = (NSDictionary)PropertyListParser.parse(file);
                
                Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME, moduleName, rootDict.get("ProductName").toString()));
                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PRODUCT_ID, moduleName, rootDict.get("ProductUserVisibleVersion").toString()));
                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VERSION, moduleName, rootDict.get("ProductBuildVersion").toString()));

                // Check if there is already an OS_INFO artifact for this file, and add to that if possible.
                ArrayList<BlackboardArtifact> results = tskCase.getBlackboardArtifacts(ARTIFACT_TYPE.TSK_OS_INFO, osVersion.getId());
                if (results.isEmpty()) {
                    newArtifacts.add(createArtifactWithAttributes(BlackboardArtifact.Type.TSK_OS_INFO, osVersion, bbattributes));
                } else {
                    results.get(0).addAttributes(bbattributes);
                }                
            } catch (ParserConfigurationException | SAXException | ParseException | IOException | TskCoreException | PropertyListFormatException ex) {
                this.addErrorMessage(NbBundle.getMessage(this.getClass(), "Process_OsVersion_Plist_File"));
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Process_OsVersion_Plist_File"), ex); //NON-NLS
                return;
            }

        }

        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }

    /**
     * get installed Programs from plist
     *
     * @param plistFileName   File Name of the plist to parse
     * @param plistFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getInstalledPrograms(String plistFileName, String plistFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> installedPrograms;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();

        try {
            installedPrograms = fileManager.findFiles(dataSource, plistFileName, plistFileLocation); //NON-NLS            
        } catch (TskCoreException ex) {
            this.addErrorMessage(NbBundle.getMessage(this.getClass(), "Progress_Message_Plist"));
            logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Progress_Message_Plist"), ex); //NON-NLS
            return;  // No need to continue
        }
        
        for (AbstractFile installedProgram : installedPrograms) {

            String installedProgramFileName = tempDirPath + File.separator + installedProgram.getId() + "_" + installedProgram.getName();

            try {
                ContentUtils.writeToFile(installedProgram, new File(installedProgramFileName));
            } catch (IOException ex) {
                this.addErrorMessage(NbBundle.getMessage(this.getClass(), "Extract_Installed_Programs_Write_File"));
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Extract_Installed_Programs_Write_File"), ex); //NON-NLS
                return;
            }
           
            try {
                File file = new File(installedProgramFileName);
                NSArray rootDict = (NSArray) PropertyListParser.parse(file);
                NSObject[] parameters = rootDict.getArray();
                for (NSObject nsdict : parameters) {
                    NSDictionary dict = (NSDictionary) nsdict;
                    Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                    String programName = dict.get("displayName").toString(); 
                    String programVersion = dict.get("displayVersion").toString();
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME, moduleName, programName));
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VERSION, moduleName, programVersion));
                    SimpleDateFormat dateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", US);
                    Long dateLong = Long.valueOf(0);
                    try {
                        Date newDate = dateFormat.parse(dict.get("date").toString());
                        dateLong = newDate.getTime() / 1000;
                    } catch (ParseException ex) {
                        // catching error and displaying date that could not be parsed
                        // we set the timestamp to 0 and continue on processing
                        logger.log(Level.WARNING, String.format("Failed to parse date/time %s Installed Program.", dict.get("date").toString()), ex); //NON-NLS
                    }
                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, dateLong));

                    newArtifacts.add(createArtifactWithAttributes(BlackboardArtifact.Type.TSK_INSTALLED_PROG, installedProgram, bbattributes));
                }
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File")); //NON-NLS
                
            } catch (ParserConfigurationException | SAXException | TskCoreException | ParseException | IOException | PropertyListFormatException ex) {
                this.addErrorMessage(NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"));
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"), ex); //NON-NLS
                return;
            }

        }

        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }
    
        private void loadXMLFile(String xmlFilePath) {
        try {
          File file = new File(xmlFilePath);
          NSObject rootDict = PropertyListParser.parse(file);
          NSDictionary rootDict2 = (NSDictionary)PropertyListParser.parse(file);
          String name = rootDict2.objectForKey("Name").toString();
          NSObject[] parameters = ((NSArray)rootDict2.objectForKey("Parameters")).getArray();
          for(NSObject param:parameters) {
            if(param.getClass().equals(NSNumber.class)) {
              NSNumber num = (NSNumber)param;
              switch(num.type()) {
                case NSNumber.BOOLEAN : {
                  boolean bool = num.boolValue();
                  //...
                  break;
                }
                case NSNumber.INTEGER : {
                  long l = num.longValue();
                  //or int i = num.intValue();
                  //...
                  break;
                }
                case NSNumber.REAL : {
                  double d = num.doubleValue();
                  //...
                  break;
                }
              }
            }
            // else...
          }
        } catch(Exception ex) {
          logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Progress_Message_Plist"), ex);
        }
    }
}
