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

import com.dd.plist.NSArray;
import com.dd.plist.NSData;
import com.dd.plist.NSDictionary;
import com.dd.plist.NSNumber;
import com.dd.plist.NSObject;
import com.dd.plist.NSString;
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
import static java.util.Locale.US;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.lang.StringUtils;
import org.openide.util.NbBundle.Messages;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.TskCoreException;
import org.xml.sax.SAXException;

/**
 * Parse Plists
 */
class ParsePlists extends Extract {

    private final Logger logger = Logger.getLogger(this.getClass().getName());
    private Content dataSource;
    private final IngestJobContext context;
    private final String moduleName;

    Blackboard blkBoard;
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    
    private static final Map<String, String> XML_PLISTS_MAP = ImmutableMap.<String, String>builder()
            .put("SystemVersion.plist", "/System/Library/CoreServices")
            .put("InstallHistory.plist", "Library/Receipts")
//            .put("MobileMeAccounts.plist", "Library/Preferences")
            .put("com.apple.airport.preferences.plist", "Library/Preferences/SystemConfiguration")
            .put("com.apple.airport.preferences.plist.backup", "Library/Preferences/SystemConfiguration")
            .put("com.apple.wifi.known-networks.plist", "Library/Preferences")
//            .put("appList.dat", "Library/Application Support/com.apple.spotlight")
            .put("com.apple.dock.plist", "/Library/Preferences")
            .put("com.apple.Bluetooth.plist", "/Library/Preferences/")
            .put("preferences.plist", "/Library/Preferences/SystemConfiguration")
            .put("NetworkInterfaces.plist", "Library/Preferences/SystemConfiguration")
            .build();

    private static final Map<String, String> PROCESS_XML_PLISTS_MAP = ImmutableMap.<String, String>builder()
            .put("SystemVersion.plist", "osInfo")
           .put("InstallHistory.plist", "installedPrograms")
            .put("MobileMeAccounts.plist", "mobileMe")
            .put("com.apple.airport.preferences.plist", "airport_prefs")
            .put("com.apple.airport.preferences.plist.backup", "airport_prefs")
            .put("com.apple.wifi.known-networks.plist", "airport_prefs")
            .put("appList.dat", "appList")
            .put("com.apple.dock.plist", "dockItems")
            .put("com.apple.Bluetooth.plist", "bluetooth")
            .put("preferences.plist", "preferences")
            .put("NetworkInterfaces.plist", "networkInterfaces")
            .build();

    @Messages({"Progress_Message_Plist=Processing pList",
               "ParsePlist.displayName=ParsePlists",
               "Progress.Message.OS.Version=Processing OS Version",
               "Progress.Message.Installed_Programs=Processing Installed Programs",
               "Progress.Message.Mobileme=Processing Mobile Me",
               "Progress.Message.Airport.Prefs=Processing Airport Prefs",
               "Progress.Message.Airport.Applist=Processing Application Lists",
               "Progress.Message.Dock.Items=Processing Dock Items",
               "Progress.Message.Bluetooth=Processing Bluetooth",
               "Progress.Message.Network_Interfaces=Processing Network Interfaces",
               "Progress.Message.Preferences=Processing Preferences",
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

        try {
            blkBoard = Case.getCurrentCaseThrows().getSleuthkitCase().getBlackboard();
        } catch (NoCurrentCaseException ex) {
            logger.log(Level.SEVERE, "Cannot get Current Case", ex); //NON-NLS
            return;            
        }
        
        for (Map.Entry<String, String> xmlPlists : XML_PLISTS_MAP.entrySet()) {
            String plistName = xmlPlists.getKey();
            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Plist"));
            switch (PROCESS_XML_PLISTS_MAP.get(plistName)) {
                case "osInfo":
//                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_OS_Version"));
                    this.getVersion(xmlPlists.getKey(), xmlPlists.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "installedPrograms":
//                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Installed_Programs"));
                    this.getInstalledPrograms(xmlPlists.getKey(), xmlPlists.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "mobileMe":
//                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Messasge_Mobileme"));
                    this.getMobileMe(xmlPlists.getKey(), xmlPlists.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "airport_prefs":
//                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Airport_Prefs"));
                    this.getAirportPrefs(xmlPlists.getKey(), xmlPlists.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "appList":
//                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Applist"));
                    this.getAppList(xmlPlists.getKey(), xmlPlists.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "dockItems":
//                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Dock_Items"));
                    this.getDockItems(xmlPlists.getKey(), xmlPlists.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "bluetooth":
//                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Bluetooth"));
                    this.getBluetooth(xmlPlists.getKey(), xmlPlists.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "preferences":
//                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Preferences"));
                    this.getPreferences(xmlPlists.getKey(), xmlPlists.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                case "networkInterfaces":
//                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Network_Interfaces"));
                    this.getNetworkInterfaces(xmlPlists.getKey(), xmlPlists.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                default:
                    logger.log(Level.WARNING, String.format("No XML Plists named %s to Parse", plistName)); //NON-NLS
                    break;
            }
            

        }

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
            osVersions = writeFileToTemp(plistFileName, plistFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write plist file file name %s and location %s and temp dire path %s.", plistFileName, plistFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
        
        for (AbstractFile osVersion : osVersions) {

            if (osVersion.getName().contains("-slack") || !osVersion.getParentPath().startsWith(plistFileLocation)) {
                continue;
            }
            
            String osVersionFileName = tempDirPath + File.separator + osVersion.getId() + "_" + osVersion.getName();
            
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
            installedPrograms = writeFileToTemp(plistFileName, plistFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write plist file file name %s and location %s and temp dire path %s.", plistFileName, plistFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
        
        for (AbstractFile installedProgram : installedPrograms) {

            String fName = installedProgram.getName();
            String fPath = installedProgram.getParentPath();

            if (installedProgram.getName().contains("-slack") || !installedProgram.getParentPath().contains(plistFileLocation)) {
                continue;
            }
            
            String installedProgramFileName = tempDirPath + File.separator + installedProgram.getId() + "_" + installedProgram.getName();

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
    
    /**
     * get mobileMe from plist
     *
     * @param plistFileName   File Name of the plist to parse
     * @param plistFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getMobileMe(String plistFileName, String plistFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> mobileMes;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();

        try {
            mobileMes = writeFileToTemp(plistFileName, plistFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write plist file file name %s and location %s and temp dire path %s.", plistFileName, plistFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
        
        for (AbstractFile mobileMe : mobileMes) {

            if (mobileMe.getName().contains("-slack") || !mobileMe.getParentPath().contains(plistFileLocation)) {
                continue;
            }
            
            String mobileMeFileName = tempDirPath + File.separator + mobileMe.getId() + "_" + mobileMe.getName();

            try {
//                  loadXMLFile(mobileMeFileName);
                  File file = new File(mobileMeFileName);
                  NSDictionary rootDict = (NSDictionary)PropertyListParser.parse(file);
                  NSArray rootValue = (NSArray) rootDict.get("Accounts");
                  NSObject[] parameters = rootValue.getArray();
                  for (NSObject nsdict : parameters) {
                    NSDictionary dict = (NSDictionary) nsdict;
                    Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                    String accountSid = dict.get("AccountAlternateDSID").toString(); 
//                    String accountId = dict.get("AccountID").toString();
//                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME, moduleName, programName));
//                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_VERSION, moduleName, programVersion));
//                    SimpleDateFormat dateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", US);
//                    Long dateLong = Long.valueOf(0);
//                    try {
//                        Date newDate = dateFormat.parse(dict.get("date").toString());
//                        dateLong = newDate.getTime() / 1000;
//                    } catch (ParseException ex) {
                        // catching error and displaying date that could not be parsed
                        // we set the timestamp to 0 and continue on processing
//                        logger.log(Level.WARNING, String.format("Failed to parse date/time %s Installed Program.", dict.get("date").toString()), ex); //NON-NLS
//                    }
//                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, dateLong));

//                    newArtifacts.add(createArtifactWithAttributes(BlackboardArtifact.Type.TSK_INSTALLED_PROG, installedProgram, bbattributes));
                }
//                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File")); //NON-NLS
                
            } catch (ParserConfigurationException | SAXException | ParseException | IOException | PropertyListFormatException ex) {
                this.addErrorMessage(NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"));
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"), ex); //NON-NLS
                return;
            }

        }

        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }

    /**
     * get airportPrefs artifacts
     *
     * @param plistFileName   File Name of the plist to parse
     * @param plistFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getAirportPrefs(String plistFileName, String plistFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> airportPrefs;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();

        try {
            airportPrefs = writeFileToTemp(plistFileName, plistFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write plist file file name %s and location %s and temp dire path %s.", plistFileName, plistFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
        
        for (AbstractFile airportPref : airportPrefs) {
            
            if (airportPref.getName().contains("-slack") || !airportPref.getParentPath().contains(plistFileLocation)) {
                continue;
            }
            
            String airportPrefFileName = tempDirPath + File.separator + airportPref.getId() + "_" + airportPref.getName();

            try {
                  File file = new File(airportPrefFileName);
                  NSDictionary rootDict = (NSDictionary)PropertyListParser.parse(file);
                  NSDictionary knownNetworkValues = (NSDictionary) rootDict.get("KnownNetworks");
                  String[] knownNetworkKeys = knownNetworkValues.allKeys();
                  for (String knownNetwork : knownNetworkKeys) {
                      NSDictionary dict = (NSDictionary) knownNetworkValues.get(knownNetwork);
                      Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                      String ssid = dict.get("SSIDString").toString(); 
                      SimpleDateFormat dateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", US);
                      Long lastAutoJoinAt = Long.valueOf(0);
                      try {
                          Date newDate = dateFormat.parse(dict.get("LastAutoJoinAt").toString());
                          lastAutoJoinAt = newDate.getTime() / 1000;
                      } catch (ParseException ex) {
                        // catching error and displaying date that could not be parsed
                        // we set the timestamp to 0 and continue on processing
                          logger.log(Level.WARNING, String.format("Failed to parse date/time %s Installed Program.", dict.get("date").toString()), ex); //NON-NLS
                      }
                      bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_SSID, moduleName, ssid));
                      bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, lastAutoJoinAt));

                    newArtifacts.add(createArtifactWithAttributes(BlackboardArtifact.Type.TSK_WIFI_NETWORK, airportPref, bbattributes));
                }
                
            } catch (ParserConfigurationException | TskCoreException | SAXException | ParseException | IOException | PropertyListFormatException ex) {
                this.addErrorMessage(NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"));
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"), ex); //NON-NLS
                return;
            }

        }

        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }

    /**
     * get appList artifacts
     *
     * @param plistFileName   File Name of the plist to parse
     * @param plistFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getAppList(String plistFileName, String plistFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> appLists;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();

        try {
            appLists = writeFileToTemp(plistFileName, plistFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write plist file file name %s and location %s and temp dire path %s.", plistFileName, plistFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
        
        for (AbstractFile appList : appLists) {

            if (appList.getName().contains("-slack") || !appList.getParentPath().contains(plistFileLocation)) {
                continue;
            }
            
            String appListFileName = tempDirPath + File.separator + appList.getId() + "_" + appList.getName();

            loadXMLFile(appListFileName);

        }

        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }

    /**
     * get Dockitems artifacts
     *
     * @param plistFileName   File Name of the plist to parse
     * @param plistFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getDockItems(String plistFileName, String plistFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> dockItems;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();
        String[] dockItemList = {"persistent-others", "persistent-apps", "recent-apps"};
        
        try {
            dockItems = writeFileToTemp(plistFileName, plistFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write plist file file name %s and location %s and temp dire path %s.", plistFileName, plistFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
        
        for (AbstractFile dockItem : dockItems) {
            
            if (dockItem.getName().contains("-slack") || !dockItem.getParentPath().contains(plistFileLocation)) {
                continue;
            }
            
 // Remove this line for production.  Only used for my testing dataset
            if (dockItem.getParentPath().contains("surge")) {
               continue;
            }
            
            String userName = getUsernameFromPath(dockItem.getParentPath(), plistFileLocation);

            String dockItemFileName = tempDirPath + File.separator + dockItem.getId() + "_" + dockItem.getName();

            try {
                BlackboardArtifact.Type customArtifactType = blkBoard.getOrAddArtifactType("RA_DOCK_ITEMS", "Macos Dock Items");
                BlackboardAttribute.Type customAttrbiuteType = blkBoard.getOrAddAttributeType("RA_RECENTLY_USED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Recently Used");
                BlackboardAttribute.Type parentModifiedAttribute = blkBoard.getOrAddAttributeType("RA_PARENT_MODIFIED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Parent Modified");
                File file = new File(dockItemFileName);
                NSDictionary rootDict = (NSDictionary)PropertyListParser.parse(file);
                for (String dItem : dockItemList) {
                    NSArray rootValue = (NSArray) rootDict.get(dItem);
                    if (rootValue != null) {
                        NSObject[] parameters = rootValue.getArray();

                        for (NSObject nsDict : parameters) {
                            NSDictionary dict = (NSDictionary) nsDict;
                            if (dict.containsKey("tile-data")) {
                               Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                               NSDictionary tileDict = (NSDictionary) dict.get("tile-data"); 
                               bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME, moduleName, tileDict.get("file-label").toString()));
                               NSNumber fileModDate = (NSNumber) tileDict.get("file-mod-date");
                               Long fileModDt = getHfsDate(fileModDate.longValue());
                               NSNumber parentModDate = (NSNumber) tileDict.get("parent-mod-date");
                               Long parentModDt = getHfsDate(parentModDate.longValue());
                               NSDictionary filePath = (NSDictionary) tileDict.get("file-data");

                               bbattributes.add(new BlackboardAttribute(parentModifiedAttribute, moduleName, parentModDt));                              
                               bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME_MODIFIED, moduleName, parentModDt));
                               bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PATH, moduleName, filePath.get("_CFURLString").toString()));
                               bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_USER_NAME, moduleName, userName));                               
                               if (dItem.contains("recent-apps")) {
                                   bbattributes.add(new BlackboardAttribute(customAttrbiuteType, moduleName, "Yes"));                           
                               }
                               newArtifacts.add(createArtifactWithAttributes(customArtifactType, dockItem, bbattributes));
                            }
                        }
                    }
                }
//                newArtifacts.add(createArtifactWithAttributes(customArtifactType, dockItem, bbattributes));
            } catch (ParserConfigurationException | BlackboardException | TskCoreException | SAXException | ParseException | IOException | PropertyListFormatException ex) {
                this.addErrorMessage(NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"));
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"), ex); //NON-NLS
                return;
            }

        }
       

        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }

    /**
     * get bluetooth artifacts
     *
     * @param plistFileName   File Name of the plist to parse
     * @param plistFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getBluetooth(String plistFileName, String plistFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> bluetooths;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();
        
        try {
            bluetooths = writeFileToTemp(plistFileName, plistFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write plist file file name %s and location %s and temp dire path %s.", plistFileName, plistFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
        
        for (AbstractFile bluetooth : bluetooths) {
            
            if (bluetooth.getName().contains("-slack") || !bluetooth.getParentPath().contains(plistFileLocation)) {
                continue;
            }
            
 // Remove this line for production.  Only used for my testing dataset
            if (bluetooth.getParentPath().contains("surge")) {
               continue;
            }
            
            String bluetoothFileName = tempDirPath + File.separator + bluetooth.getId() + "_" + bluetooth.getName();

            try {
                File file = new File(bluetoothFileName);
                NSDictionary rootDict = (NSDictionary)PropertyListParser.parse(file);
                NSDictionary deviceCache = (NSDictionary) rootDict.get("DeviceCache");
                if (deviceCache != null) {
                    NSArray pariedDevices = (NSArray) rootDict.get("BRPairedDevices");
                    String[] deviceCacheKeys = deviceCache.allKeys();
                    for (String deviceCacheKey : deviceCacheKeys) {
                        NSDictionary device = (NSDictionary) deviceCache.get(deviceCacheKey);
                        Collection<BlackboardAttribute> bbattributesBta = new ArrayList<>();
                        Collection<BlackboardAttribute> bbattributesBtp = new ArrayList<>();
                        bbattributesBta.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_MAC_ADDRESS, moduleName, deviceCacheKey));
                        bbattributesBta.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME, moduleName, device.get("Name").toString()));
                        SimpleDateFormat dateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", US);
                        Long lastInquiry = Long.valueOf(0);
                        try {
                            Date newDate = dateFormat.parse(device.get("LastInquiryUpdate").toString());
                            lastInquiry = newDate.getTime() / 1000;
                        } catch (ParseException ex) {
                          // catching error and displaying date that could not be parsed
                          // we set the timestamp to 0 and continue on processing
                            logger.log(Level.WARNING, String.format("Failed to parse date/time %s Installed Program.", device.get("date").toString()), ex); //NON-NLS
                        }
                        bbattributesBta.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, lastInquiry));
                        newArtifacts.add(createArtifactWithAttributes(BlackboardArtifact.Type.TSK_BLUETOOTH_ADAPTER, bluetooth, bbattributesBta));
                        if (pariedDevices.containsObject(deviceCacheKey) ) {
                            bbattributesBtp.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_MAC_ADDRESS, moduleName, deviceCacheKey));
                            bbattributesBtp.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DEVICE_NAME, moduleName, device.get("Name").toString()));
                            bbattributesBta.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, lastInquiry));
                            newArtifacts.add(createArtifactWithAttributes(BlackboardArtifact.Type.TSK_BLUETOOTH_PAIRING, bluetooth, bbattributesBtp));
                        }
                    }
                }
            } catch (ParserConfigurationException | TskCoreException | SAXException | ParseException | IOException | PropertyListFormatException ex) {
                this.addErrorMessage(NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"));
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"), ex); //NON-NLS
                return;
            }

        }
       

        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }

    /**
     * get preferences artifacts
     *
     * @param plistFileName   File Name of the plist to parse
     * @param plistFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getPreferences(String plistFileName, String plistFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> preferences;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();
        
        try {
            preferences = writeFileToTemp(plistFileName, plistFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write plist file file name %s and location %s and temp dire path %s.", plistFileName, plistFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
        
        BlackboardArtifact.Type networkArtifactType;
        BlackboardAttribute.Type uuidTypeAttribute;
        BlackboardAttribute.Type ipv4Attribute;
        BlackboardAttribute.Type ipv6Attribute;
        BlackboardAttribute.Type hardwareAttribute;
        BlackboardAttribute.Type typeAttribute;
        BlackboardAttribute.Type userDefinedNameAttribute;
 
        try {
            networkArtifactType = blkBoard.getOrAddArtifactType("RA_NETWORK_DETAILS", "Network Details");
            uuidTypeAttribute = blkBoard.getOrAddAttributeType("RA_UUID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "UUID");
            ipv4Attribute = blkBoard.getOrAddAttributeType("RA_WIFI_IN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IPv4 ConfigMethod");
            ipv6Attribute = blkBoard.getOrAddAttributeType("RA_WIFI_OUT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IPv6 ConfigMethod");
            hardwareAttribute = blkBoard.getOrAddAttributeType("RA_HARDWARE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Hardware");
            typeAttribute = blkBoard.getOrAddAttributeType("RA_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Type");
            userDefinedNameAttribute = blkBoard.getOrAddAttributeType("RA_USER_DEFINED_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User Defined Name");
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, "Cannot create artifact/attributes for network usage", ex);//NON-NLS
            return;    
        }

        for (AbstractFile preference : preferences) {
            
            if (preference.getName().contains("-slack") || !preference.getParentPath().contains(plistFileLocation)) {
                continue;
            }
            
 // Remove this line for production.  Only used for my testing dataset
            if (preference.getParentPath().contains("surge")) {
               continue;
            }
            
            String preferenceFileName = tempDirPath + File.separator + preference.getId() + "_" + preference.getName();

            try {
                File file = new File(preferenceFileName);
                NSDictionary rootDict = (NSDictionary)PropertyListParser.parse(file);
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File")); //NON-NLS
                NSDictionary networkServices = (NSDictionary) rootDict.get("NetworkServices");
                if (networkServices != null) {
                    String[] networkServicesKeys = networkServices.allKeys();
                    for (String networkServiceKey : networkServicesKeys) {
                        NSDictionary networkService = (NSDictionary) networkServices.get(networkServiceKey);
                        Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                        bbattributes.add(new BlackboardAttribute(uuidTypeAttribute, moduleName, networkServiceKey));
                        NSDictionary dict = (NSDictionary) networkService.get("IPv4");
                        bbattributes.add(new BlackboardAttribute(ipv4Attribute, moduleName, dict.get("ConfigMethod").toString()));
                        dict = (NSDictionary) networkService.get("IPv6");
                        bbattributes.add(new BlackboardAttribute(ipv6Attribute, moduleName, dict.get("ConfigMethod").toString()));
                        dict = (NSDictionary) networkService.get("Interface");
                        bbattributes.add(new BlackboardAttribute(hardwareAttribute, moduleName, dict.get("Hardware").toString()));
                        bbattributes.add(new BlackboardAttribute(typeAttribute, moduleName, dict.get("Type").toString()));
                        bbattributes.add(new BlackboardAttribute(userDefinedNameAttribute, moduleName, dict.get("UserDefinedName").toString()));
                        newArtifacts.add(createArtifactWithAttributes(networkArtifactType, preference, bbattributes));
                    }
                }
            } catch (ParserConfigurationException | TskCoreException | SAXException | ParseException | IOException | PropertyListFormatException ex) {
                this.addErrorMessage(NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"));
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File"), ex); //NON-NLS
                return;
            }
        }

        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }

    /**
     * get networkinterfaces artifacts
     *
     * @param plistFileName   File Name of the plist to parse
     * @param plistFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getNetworkInterfaces(String plistFileName, String plistFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> absFiles;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();
        
        try {
            absFiles = writeFileToTemp(plistFileName, plistFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write plist file file name %s and location %s and temp dire path %s.", plistFileName, plistFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
        
        BlackboardArtifact.Type networkArtifactType;
        BlackboardAttribute.Type categoryAttribute;
        BlackboardAttribute.Type bsdNameAttribute;
        BlackboardAttribute.Type activeAttribute;
        BlackboardAttribute.Type ioBuiltinAttribute;
        BlackboardAttribute.Type ioInterfaceNamePrefixAttribute;
        BlackboardAttribute.Type ioInterfaceTypeAttribute;
        BlackboardAttribute.Type ioInterfaceUnitAttribute;
        BlackboardAttribute.Type ioMacAddressAttribute;
        BlackboardAttribute.Type ioPathMatchAttribute;
        BlackboardAttribute.Type scNetworkInterfaceInfoAttribute;
        BlackboardAttribute.Type scNetworkInterfaceTypeAttribute;
 
        try {
            networkArtifactType = blkBoard.getOrAddArtifactType("RA_NETWORK_INTERFACES", "Network Interfaces");
            categoryAttribute = blkBoard.getOrAddAttributeType("RA_CATEGORY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Category");
            bsdNameAttribute = blkBoard.getOrAddAttributeType("RA_BSD_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "BSD Name");
            activeAttribute = blkBoard.getOrAddAttributeType("RA_ACTIVE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Active");
            ioBuiltinAttribute = blkBoard.getOrAddAttributeType("RA_IO_BUILTIN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IO Bulitin");
            ioInterfaceNamePrefixAttribute = blkBoard.getOrAddAttributeType("RA_IO_INTERFACE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IO Interface Name Prefix");
            ioInterfaceTypeAttribute = blkBoard.getOrAddAttributeType("RA_IO_INTERFACE_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IO Interface Type");
            ioInterfaceUnitAttribute = blkBoard.getOrAddAttributeType("RA_IO_INTERFACE_UNIT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IO Interface Unit");
            ioMacAddressAttribute = blkBoard.getOrAddAttributeType("RA_MAC_ADDRESS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IO Mac Address");
            ioPathMatchAttribute = blkBoard.getOrAddAttributeType("RA_IO_PATH_MATCH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "IO Path Matchi");
            scNetworkInterfaceInfoAttribute = blkBoard.getOrAddAttributeType("RA_SC_INTERFACE_INFO", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SC Network Interface Name");
            scNetworkInterfaceTypeAttribute = blkBoard.getOrAddAttributeType("RA_SC_INTERFACE_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "SC Netowrk Interface Type");
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, "Cannot create artifact/attributes for network usage", ex);//NON-NLS
            return;    
        }

        for (AbstractFile absFile : absFiles) {
            
            if (absFile.getName().contains("-slack") || !absFile.getParentPath().contains(plistFileLocation)) {
                continue;
            }
            
 // Remove this line for production.  Only used for my testing dataset
            if (absFile.getParentPath().contains("surge")) {
               continue;
            }
            
            String absFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();

            try {
                File file = new File(absFileName);
                NSDictionary rootDict = (NSDictionary)PropertyListParser.parse(file);
                logger.log(Level.WARNING, NbBundle.getMessage(this.getClass(), "Process_Installed_Programs_Plist_File")); //NON-NLS
                NSArray networkInterfaces = (NSArray) rootDict.get("Interfaces");
                NSObject[] parameters = networkInterfaces.getArray();
                for (NSObject nsdict : parameters) {
                    NSDictionary dict = (NSDictionary) nsdict;

                    Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                    bbattributes.add(new BlackboardAttribute(categoryAttribute, moduleName, "Interfaces"));
                    NSString bsdName = (NSString) dict.get("BSD Name");
                    bbattributes.add(new BlackboardAttribute(bsdNameAttribute, moduleName, bsdName.getContent()));
                    String active = "";
                    if (dict.containsKey("Active")) {
                        active = "True";
                    }
                    bbattributes.add(new BlackboardAttribute(activeAttribute, moduleName, active));
                    NSNumber ioBuiltin = (NSNumber) dict.get("IOBuiltin");
                    if (ioBuiltin.boolValue()) {
                        bbattributes.add(new BlackboardAttribute(ioBuiltinAttribute, moduleName, "True"));
                    } else {                        
                        bbattributes.add(new BlackboardAttribute(ioBuiltinAttribute, moduleName, "False"));
                    }
                    bbattributes.add(new BlackboardAttribute(ioInterfaceNamePrefixAttribute, moduleName, dict.get("IOInterfaceNamePrefix").toString()));
                    bbattributes.add(new BlackboardAttribute(ioInterfaceTypeAttribute, moduleName, dict.get("IOInterfaceType").toString()));
                    bbattributes.add(new BlackboardAttribute(ioInterfaceUnitAttribute, moduleName, dict.get("IOInterfaceUnit").toString()));
                    NSData ioMacAddress = (NSData) dict.get("IOMACAddress");
                    byte[] ioMac = ioMacAddress.bytes();
                    String macAddress = bytesToHex(ioMac, ":");
                    bbattributes.add(new BlackboardAttribute(ioMacAddressAttribute, moduleName, macAddress));
                    bbattributes.add(new BlackboardAttribute(ioPathMatchAttribute, moduleName, dict.get("IOPathMatch").toString()));
                    bbattributes.add(new BlackboardAttribute(scNetworkInterfaceInfoAttribute, moduleName, dict.get("SCNetworkInterfaceInfo").toString()));
                    bbattributes.add(new BlackboardAttribute(scNetworkInterfaceTypeAttribute, moduleName, dict.get("SCNetworkInterfaceType").toString()));
                    newArtifacts.add(createArtifactWithAttributes(networkArtifactType, absFile, bbattributes));
                    }
            } catch (ParserConfigurationException | TskCoreException | SAXException | ParseException | IOException | PropertyListFormatException ex) {
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
//          NSObject rootDict = PropertyListParser.parse(file);
          NSDictionary rootDict2 = (NSDictionary)PropertyListParser.parse(file);
          NSArray rootValue = (NSArray) rootDict2.get("Accounts");
          String name = rootDict2.objectForKey("key").toString();
          NSObject[] parameters = ((NSArray)rootDict2.objectForKey("array")).getArray();
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
    
    private long getHfsDate(long numberOfSeconds) {

        long numOfSeconds = numberOfSeconds;
        
        if (numberOfSeconds > 0xFFFFFFFF) {
            numOfSeconds = numberOfSeconds & 0xFFFFFFFF;
        }
        
        long hfsLinuxTimeDifference = 2082844800;
        
        return Math.abs(numOfSeconds) - hfsLinuxTimeDifference;
    }

    private String getUsernameFromPath(String parentPath, String plistFileLocation) {
        
        String newPath = parentPath.replace(plistFileLocation + '/', "");
        int lastSlash = newPath.lastIndexOf('/');
        String userName = newPath.substring(lastSlash + 1);
        int x = 1;
        return userName;
    }
    
    private List<AbstractFile> writeFileToTemp(String fileName, String fileLocation, String tempDirPath) throws TskCoreException, IOException{
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> absFiles = new ArrayList<>();

        try {
            absFiles = fileManager.findFiles(dataSource, fileName + '%', fileLocation); //NON-NLS            
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, String.format("Error getting files for %s in path %s", fileName, fileLocation), ex); //NON-NLS
            throw new TskCoreException(String.format("Error getting files for %s in path %s", fileName, fileLocation));
        }
        
        for (AbstractFile absFile : absFiles) {
            
            String tempFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();

            try {
                ContentUtils.writeToFile(absFile, new File(tempFileName));
            } catch (IOException ex) {
                logger.log(Level.WARNING, String.format("Cannot write file to temp directory, file name is %s and file path is %s", fileName, fileLocation), ex); //NON-NLS
                throw new IOException(String.format("Error getting files for %s in path %s", fileName, fileLocation));
            }
        }
        
        return absFiles;
    }
 
    public static String bytesToHex(byte[] bytes, String formatSeperator) {
        char[] hexChars = new char[bytes.length * 2];
        String hexString = "";
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
            hexString = hexString + HEX_ARRAY[v >>> 4] + HEX_ARRAY[v & 0x0F] + formatSeperator; 
        }
        String formattedString = "";
        for (char hexChar : hexChars) {
            formattedString = hexChar + ":";
        }
        return StringUtils.chop(hexString);
}
}
