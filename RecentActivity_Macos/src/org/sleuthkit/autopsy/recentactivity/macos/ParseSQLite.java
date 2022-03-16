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

import com.google.common.collect.ImmutableMap;
import org.openide.util.NbBundle;
import org.sleuthkit.autopsy.datamodel.ContentUtils;
import java.util.logging.Level;
import java.io.File;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import org.openide.util.Exceptions;
import org.openide.util.NbBundle.Messages;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.SQLiteDBConnect;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.TskCoreException;

/**
 * Parse Plists
 */
class ParseSQLite extends Extract {

    private final Logger logger = Logger.getLogger(this.getClass().getName());
    private Content dataSource;
    private final IngestJobContext context;
    private final String moduleName;

    Blackboard blkBoard;
    
    private static final Map<String, String> SQLITE_MAP = ImmutableMap.<String, String>builder()
            .put("chat.db", "/Library/Messages")
//            .put("db", "com.apple.notificationcenter/db%")
            .put("netusage.sqlite", "var/networkd")
            .put("com.apple.LaunchServices.QuarantineEventsV2", "Library/Preferences")
            .build();

    private static final Map<String, String> PROCESS_SQLITE_MAP = ImmutableMap.<String, String>builder()
            .put("chat.db", "iMessages")
//            .put("db", "notifications")
            .put("netusage.sqlite", "netusage")
            .put("com.apple.LaunchServices.QuarantineEventsV2", "quarantine")
            .build();

    @Messages({"Progress_Message_Sqlite=Processing Sqlite",
               "ParseSqlite.displayName=ParseSqlite",
               "Progress_Message_IMessage=Processing iMessages",
               "Progress_Message_Notifications=Processing Notifications",
               "Progress_Message_Netusage=Processing Netusage",
               "Progress_Message_Quarantine=Processing Quarantine",
    })

    ParseSQLite(IngestJobContext context) {
        super(Bundle.ParseSqlite_displayName(), context);
        this.context = context;
        moduleName = NbBundle.getMessage(Chromium.class, "ParseSQLite.moduleName");
    }

    @Override
    public void process(Content dataSource, DataSourceIngestModuleProgress progressBar) {
        this.dataSource = dataSource;
        dataFound = false;
        long ingestJobId = context.getJobId();
        
        String tempDirPath = RAImageIngestModule.getRATempPath(Case.getCurrentCase(), "sqlite", context.getJobId()); //NON-NLS

        try {
            blkBoard = Case.getCurrentCaseThrows().getSleuthkitCase().getBlackboard();
        } catch (NoCurrentCaseException ex) {
            logger.log(Level.SEVERE, "Cannot get Current Case", ex); //NON-NLS
            return;            
        }
        
        for (Map.Entry<String, String> sqliteDb : SQLITE_MAP.entrySet()) {
            String sqliteDbName = sqliteDb.getKey();
            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Sqlite"));
            switch (PROCESS_SQLITE_MAP.get(sqliteDbName)) {
                case "iMessages":
                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_IMessage"));
                    getIMessages(sqliteDb.getKey(), sqliteDb.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "notifications":
                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Notifications"));
                    getNotifications(sqliteDb.getKey(), sqliteDb.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "netusage":
                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Netusage"));
                    getNetusage(sqliteDb.getKey(), sqliteDb.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "quarantine":
                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Quarantine"));
                    getQuarantine(sqliteDb.getKey(), sqliteDb.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                default:
                    logger.log(Level.WARNING, String.format("No sqlite database named %s to Parse", sqliteDbName)); //NON-NLS
                    break;
            }
        }       
    }

    @Messages({"Error_Finding_Sqlite_File_OsVersion=Error Finding Sqlite Database",
               "Process_Sqlite_File=Error processing Sqlite",
               "Error_Finding_Sqlite_File=Error Finding Sqlite database",
               "Extract_Sqlite_Write_File=Error Writing Sqlite database",
               "Process_Sqlite_Plist_File=Error processing Sqlite database",})
    
    /**
     * get iMessages artifacts
     *
     * @param sqliteDbName   File Name of the plist to parse
     * @param sqliteDbFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getIMessages(String sqliteDbFileName, String sqliteDbFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> sqliteDbAbsFiles;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();

        try {
            sqliteDbAbsFiles = writeFileToTemp(sqliteDbFileName, sqliteDbFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write sqlite database file file name %s and location %s and temp dire path %s.", sqliteDbFileName, sqliteDbFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
         
        for (AbstractFile absFile : sqliteDbAbsFiles) {
            if (absFile.getName().equals(sqliteDbFileName)) {
                // 978307200 is the number of seconds difference bewteen Unix Epoch time and Apple Absolute Epoch time
                String sqlStatement = "SELECT m.rowid as msg_id, m.handle_id, m.text ,c.chat_identifier as contact, " +
                  " (case when m.is_from_me == 0 then '->' when m.is_from_me == 1 then '<-' end ) as direction, " +
                  " m.account, (m.date/1000000000) + 978307200 as date, (m.date_read/1000000000) + 978307200 as date_read, " +
                  " (m.date_delivered/1000000000) + 978307200 as date_delivered, m.is_from_me, m.is_read, " +
// Need to check the column exists for this
                  " m.destination_caller_id, " +
                  " a.filename as att_path, a.transfer_name as att_name, a.total_bytes as att_size " +
                  " from message as m " +
                  " LEFT JOIN message_attachment_join as ma on ma.message_id = m.rowid " +
                  " LEFT JOIN attachment as a on a.ROWID=ma.attachment_id " +
                  " LEFT JOIN chat_message_join as cmj on cmj.message_id = m.rowid " +
                  " LEFT JOIN chat as c on c.ROWID=cmj.chat_id"; //NON-NLS

// Add message for communication mgr
// Add incoming and out going instead of what is currently there
// Add attachment
// Add associated object
                
                String sqliteFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();
                
                try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sqliteFileName); //NON-NLS
                        ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

                    while (resultSet.next()) {
                        Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_USER_ID, moduleName, resultSet.getString("account")));
                        String contact = resultSet.getString("contact");
                        if (resultSet.getString("direction").equals("<-")) {
                            if (resultSet.getString("destination_caller_id").contains("@")) {
                                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_EMAIL_FROM, moduleName, resultSet.getString("contact")));
                            } else {
                                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, moduleName, resultSet.getString("contact")));
                            }
                            bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DIRECTION, moduleName, resultSet.getString("direction")));
                            if (resultSet.getString("contact") != null) {
                                if (resultSet.getString("contact").contains("@")) {
                                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_EMAIL_TO, moduleName, resultSet.getString("destination_caller_id")));
                                } else {
                                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, moduleName, resultSet.getString("destination_caller_id")));
                                }
                            }
                        } else {
                            if (resultSet.getString("contact") != null) {
                                if (resultSet.getString("contact").contains("@")) {
                                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_EMAIL_FROM, moduleName, resultSet.getString("contact")));
                                } else {
                                    bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM, moduleName, resultSet.getString("contact")));
                                }
                            }
                            bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DIRECTION, moduleName, resultSet.getString("direction")));
                            if (resultSet.getString("destination_caller_id").contains("@")) {
                                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_EMAIL_TO, moduleName, resultSet.getString("destination_caller_id")));
                            } else {
                                bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO, moduleName, resultSet.getString("destination_caller_id")));
                            }
                        }
                        if (resultSet.getString("text") != null) {
                            bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_TEXT, moduleName, resultSet.getString("text")));
                        }
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_READ_STATUS, moduleName, resultSet.getInt("is_read")));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, Long.valueOf(resultSet.getString("date"))));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME_RCVD, moduleName, Long.valueOf(resultSet.getString("date_delivered"))));
                        
                        newArtifacts.add(createArtifactWithAttributes(BlackboardArtifact.Type.TSK_MESSAGE, absFile, bbattributes));

                        if (context.dataSourceIngestIsCancelled()) {
                            logger.log(Level.INFO, "Cancelled iMessage artifact creation."); //NON-NLS
                            return;
                        }

                    }
                }  catch (SQLException | TskCoreException ex) {
                    logger.log(Level.SEVERE, "Error while trying to read into a sqlite db.", ex);//NON-NLS
                }
            }
        }
        
        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }

    /**
     * get notifications artifacts
     *
     * @param sqliteDbName   File Name of the plist to parse
     * @param sqliteDbFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getNotifications(String sqliteDbFileName, String sqliteDbFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> sqliteDbAbsFiles;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();

        try {
            sqliteDbAbsFiles = writeFileToTemp(sqliteDbFileName, sqliteDbFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write sqlite database file file name %s and location %s and temp dire path %s.", sqliteDbFileName, sqliteDbFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
         
        for (AbstractFile absFile : sqliteDbAbsFiles) {
            if (absFile.getName().equals(sqliteDbFileName)) {
                String sqlStatement = "SELECT (SELECT identifier from app where app.app_id=record.app_id) as app, " +
                                      "     uuid, cast(data as text), presented, delivered_date FROM record"; //NON-NLS

                String sqliteFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();
                
                try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sqliteFileName); //NON-NLS
                        ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

                    while (resultSet.next()) {
                        Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_USER_ID, moduleName, resultSet.getString("account")));
                        String contact = resultSet.getString("contact");
//                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DIRECTION, moduleName, resultSet.getString("direction")));
//                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, resultSet.getString("date")));
//                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME_RCVD, moduleName, resultSet.getString("date_delivered")));
                        
                        newArtifacts.add(createArtifactWithAttributes(BlackboardArtifact.Type.TSK_PROG_NOTIFICATIONS, absFile, bbattributes));

                        if (context.dataSourceIngestIsCancelled()) {
                            logger.log(Level.INFO, "Cancelled iMessage artifact creation."); //NON-NLS
                            return;
                        }

                    }
                }  catch (SQLException | TskCoreException ex) {
                    logger.log(Level.SEVERE, "Error while trying to read into a sqlite db.", ex);//NON-NLS
                }
            }
        }
        
        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }
    
    /**
     * get netusage artifacts
     *
     * @param sqliteDbName   File Name of the plist to parse
     * @param sqliteDbFileLocation   Location of the plist file in the image
     * @param ingestJobId     The ingest job id.
     * @param tempDirPath   the temporary directory to write the plist file to
     */
    private void getNetusage(String sqliteDbFileName, String sqliteDbFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> sqliteDbAbsFiles;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();

        try {
            sqliteDbAbsFiles = writeFileToTemp(sqliteDbFileName, sqliteDbFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write sqlite database file file name %s and location %s and temp dire path %s.", sqliteDbFileName, sqliteDbFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
        
        BlackboardArtifact.Type customArtifactType;
        BlackboardAttribute.Type itemTypeAttribute;
        BlackboardAttribute.Type wifiInAttribute;
        BlackboardAttribute.Type wifiOutAttribute;
        BlackboardAttribute.Type wiredInAttribute;
        BlackboardAttribute.Type wiredOutAttribute;
        BlackboardAttribute.Type wanInAttribute;
        BlackboardAttribute.Type wanOutAttribute;
        BlackboardAttribute.Type bytesInAttribute;
        BlackboardAttribute.Type bytesOutAttribute;
        BlackboardAttribute.Type firstSeenAttribute;
        BlackboardAttribute.Type lastSeenAttribute;
        BlackboardAttribute.Type usageSinceAttribute;
 
        try {
            customArtifactType = blkBoard.getOrAddArtifactType("RA_NETWORK_USAGE", "Network Usage");
            itemTypeAttribute = blkBoard.getOrAddAttributeType("RA_ITEM_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Item Type");
            wifiInAttribute = blkBoard.getOrAddAttributeType("RA_WIFI_IN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE, "Wifi In");
            wifiOutAttribute = blkBoard.getOrAddAttributeType("RA_WIFI_OUT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE, "Wifi Out");
            wiredInAttribute = blkBoard.getOrAddAttributeType("RA_WIRED_IN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE, "Wired In");
            wiredOutAttribute = blkBoard.getOrAddAttributeType("RA_WIRED_OUT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE, "Wired Out");
            wanInAttribute = blkBoard.getOrAddAttributeType("RA_WAN_IN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE, "Wan In");
            wanOutAttribute = blkBoard.getOrAddAttributeType("RA_WAN_OUT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE, "Wan Out");
            bytesInAttribute = blkBoard.getOrAddAttributeType("RA_WAN_OUT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE, "Bytes in");
            bytesOutAttribute = blkBoard.getOrAddAttributeType("RA_WAN_OUT", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DOUBLE, "Bytes Out");
            firstSeenAttribute = blkBoard.getOrAddAttributeType("RA_FIRST_SEEN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "First Seen");
            lastSeenAttribute = blkBoard.getOrAddAttributeType("RA_LAST_SEEN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Last Seen");
            usageSinceAttribute = blkBoard.getOrAddAttributeType("RA_USAGE_SINCE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Usage Since");
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, "Cannot create artifact/attributes for network usage", ex);//NON-NLS
            return;    
        }

        
        for (AbstractFile absFile : sqliteDbAbsFiles) {
            if (absFile.getName().equals(sqliteDbFileName)) {
                String sqlStatement = "SELECT pk.z_name as item_type ,p.zprocname as process_name, " +
                                      "       cast(round(strftime('%s', '2001-01-01 00:00:00') + p.zfirsttimestamp) as int) as first_seen_date," +
                                      "       cast(round(strftime('%s', '2001-01-01 00:00:00') + p.ztimestamp) as int) as last_seen_date, " +
                                      "       cast(round(strftime('%s', '2001-01-01 00:00:00') + lu.ztimestamp) as int) as usage_since, " +
                                      "       lu.zwifiin, lu.zwifiout,lu.zwiredin,lu.zwiredout,lu.zwwanin,lu.zwwanout  " +
                                      "  FROM zprocess p LEFT JOIN zliveusage lu ON p.z_pk = lu.zhasprocess  " +
                                      "  LEFT JOIN z_primarykey pk ON p.z_ent = pk.z_ent " +
                                      " WHERE zwifiin NOT NULL OR zwifiout NOT NULL OR zwiredin NOT NULL OR zwiredout NOT NULL " +
                                      "   OR zwwanin NOT NULL OR zwwanout NOT NULL " +
                                      " ORDER BY process_name"; //NON-NLS

                String sqliteFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();
                
                try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sqliteFileName); //NON-NLS
                        ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

                    while (resultSet.next()) {
                        Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
//                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_USER_ID, moduleName, getUserNameFromPath());
                        bbattributes.add(new BlackboardAttribute(itemTypeAttribute, moduleName, resultSet.getString("item_type")));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME, moduleName, resultSet.getString("process_name")));
                        bbattributes.add(new BlackboardAttribute(firstSeenAttribute, moduleName, Long.valueOf(resultSet.getString("first_seen_date"))));
                        bbattributes.add(new BlackboardAttribute(lastSeenAttribute, moduleName, Long.valueOf(resultSet.getString("last_seen_date"))));
                        bbattributes.add(new BlackboardAttribute(usageSinceAttribute, moduleName, Long.valueOf(resultSet.getString("usage_since"))));
                        bbattributes.add(new BlackboardAttribute(wifiInAttribute, moduleName, Double.valueOf(resultSet.getString("zwifiin"))));
                        bbattributes.add(new BlackboardAttribute(wifiOutAttribute, moduleName, Double.valueOf(resultSet.getString("zwifiout"))));
                        bbattributes.add(new BlackboardAttribute(wiredInAttribute, moduleName, Double.valueOf(resultSet.getString("zwiredin"))));
                        bbattributes.add(new BlackboardAttribute(wiredOutAttribute, moduleName, Double.valueOf(resultSet.getString("zwiredout"))));
                        bbattributes.add(new BlackboardAttribute(wanInAttribute, moduleName, Double.valueOf(resultSet.getString("zwwanin"))));
                        bbattributes.add(new BlackboardAttribute(wanOutAttribute, moduleName, Double.valueOf(resultSet.getString("zwwanout"))));
                        
                        newArtifacts.add(createArtifactWithAttributes(customArtifactType, absFile, bbattributes));

                        if (context.dataSourceIngestIsCancelled()) {
                            logger.log(Level.INFO, "Cancelled netusage artifact creation."); //NON-NLS
                            return;
                        }

                    }
                }  catch (SQLException | TskCoreException ex) {
                    logger.log(Level.SEVERE, "Error while trying to read into a sqlite db.", ex);//NON-NLS
                }

                sqlStatement = "SELECT pk.z_name as item_type, na.zidentifier as item_name, " +
                                      "       cast(round(strftime('%s', '2001-01-01 00:00:00') + na.zfirsttimestamp) as int) as first_seen_date," +
                                      "       cast(round(strftime('%s', '2001-01-01 00:00:00') + na.ztimestamp) as int) as last_seen_date, " +
                                      "       cast(round(strftime('%s', '2001-01-01 00:00:00') + rp.ztimestamp) as int) as usage_since, " +
                                      "       rp.zbytesin, rp.zbytesout " +
                               "  FROM znetworkattachment as na  " +
                               "  LEFT JOIN z_primarykey pk ON na.z_ent = pk.z_ent " +
                               "  LEFT JOIN zliverouteperf rp ON rp.zhasnetworkattachment = na.z_pk " +
                               " ORDER BY pk.z_name, zidentifier, usage_since desc";
                try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sqliteFileName); //NON-NLS
                        ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

                    while (resultSet.next()) {
                        Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                        bbattributes.add(new BlackboardAttribute(itemTypeAttribute, moduleName, resultSet.getString("item_type")));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PROG_NAME, moduleName, resultSet.getString("item_name")));
                        bbattributes.add(new BlackboardAttribute(firstSeenAttribute, moduleName, Long.valueOf(resultSet.getString("first_seen_date"))));
                        bbattributes.add(new BlackboardAttribute(lastSeenAttribute, moduleName, Long.valueOf(resultSet.getString("last_seen_date"))));
                        bbattributes.add(new BlackboardAttribute(usageSinceAttribute, moduleName, Long.valueOf(resultSet.getString("usage_since"))));
                        bbattributes.add(new BlackboardAttribute(bytesInAttribute, moduleName, Double.valueOf(resultSet.getString("zbytesin"))));
                        bbattributes.add(new BlackboardAttribute(bytesOutAttribute, moduleName, Double.valueOf(resultSet.getString("zbytesout"))));
                        
                        newArtifacts.add(createArtifactWithAttributes(customArtifactType, absFile, bbattributes));

                        if (context.dataSourceIngestIsCancelled()) {
                            logger.log(Level.INFO, "Cancelled netusage artifact creation."); //NON-NLS
                            return;
                        }

                    }
                }  catch (SQLException | TskCoreException ex) {
                    logger.log(Level.SEVERE, "Error while trying to read into a sqlite db.", ex);//NON-NLS
                }
            }
        }
        
        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }
    
    private void getQuarantine(String sqliteDbFileName, String sqliteDbFileLocation, long ingestJobId, String tempDirPath) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> sqliteDbAbsFiles;
        List<BlackboardArtifact> newArtifacts = new ArrayList<>();

        try {
            sqliteDbAbsFiles = writeFileToTemp(sqliteDbFileName, sqliteDbFileLocation, tempDirPath);
        } catch (TskCoreException | IOException ex) {
            logger.log(Level.SEVERE, String.format("Error while get/write sqlite database file file name %s and location %s and temp dire path %s.", sqliteDbFileName, sqliteDbFileLocation, tempDirPath), ex);//NON-NLS
            return;    
        }
        
        BlackboardArtifact.Type customArtifactType;
        BlackboardAttribute.Type eventIdAttribute;
        BlackboardAttribute.Type agentBundleIdAttribute;
        BlackboardAttribute.Type agentNameAttribute;
        BlackboardAttribute.Type dataUrlAttribute;
        BlackboardAttribute.Type senderNameAttribute;
        BlackboardAttribute.Type senderAddressAttribute;
        BlackboardAttribute.Type typeNumberAttribute;
        BlackboardAttribute.Type originTitleAttribute;
        BlackboardAttribute.Type originUrlAttribute;
        BlackboardAttribute.Type originAliasAttribute;
 
        try {
            customArtifactType = blkBoard.getOrAddArtifactType("RA_QUARANTINE_EVENTS", "Quarantine Events");
            eventIdAttribute = blkBoard.getOrAddAttributeType("RA_EVENT_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Id");
            agentBundleIdAttribute = blkBoard.getOrAddAttributeType("RA_AGENT_BUNDLE_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Agent Bundle Id");
            agentNameAttribute = blkBoard.getOrAddAttributeType("RA_AGENT_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Agent Name");
            dataUrlAttribute = blkBoard.getOrAddAttributeType("RA_DATA_URL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Data Url");
            senderNameAttribute = blkBoard.getOrAddAttributeType("RA_SENDER_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Sender Name");
            senderAddressAttribute = blkBoard.getOrAddAttributeType("RA_SENDER_ADDRESS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Sender Address");
            typeNumberAttribute = blkBoard.getOrAddAttributeType("RA_TYPE_NUMBER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, "Type Number");
            originTitleAttribute = blkBoard.getOrAddAttributeType("RA_ORIGIN_TITLE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Origin Title");
            originUrlAttribute = blkBoard.getOrAddAttributeType("RA_ORIGIN_URL", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Origin URL");
            originAliasAttribute = blkBoard.getOrAddAttributeType("RA_ORIGIN_ALIAS", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Origin Alias");
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, "Cannot create artifact/attributes for network usage", ex);//NON-NLS
            return;    
        }

        
        for (AbstractFile absFile : sqliteDbAbsFiles) {
            if (absFile.getName().equals(sqliteDbFileName)) {
                String sqlStatement = "SELECT LSQuarantineEventIdentifier as id, cast(round(strftime('%s', '2001-01-01 00:00:00') + LSQuarantineTimeStamp) as int) as ts, " +
                                      "       LSQuarantineAgentBundleIdentifier as bundle, " +
                                      "       LSQuarantineAgentName as agent_name, LSQuarantineDataURLString as data_url, " +
                                      "       LSQuarantineSenderName as sender_name, LSQuarantineSenderAddress as sender_add, LSQuarantineTypeNumber as type_num, " +
                                      "       LSQuarantineOriginTitle as o_title, LSQuarantineOriginURLString as o_url, LSQuarantineOriginAlias as o_alias " +
                                      "  FROM LSQuarantineEvent " +
                                      " ORDER BY ts"; //NON-NLS

                String sqliteFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();
                
                try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sqliteFileName); //NON-NLS
                        ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

                    while (resultSet.next()) {
                        Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_USER_ID, moduleName, getUsernameFromPath(absFile.getParentPath(), sqliteDbFileLocation)));
                        bbattributes.add(new BlackboardAttribute(eventIdAttribute, moduleName, resultSet.getString("id")));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, Long.valueOf(resultSet.getString("ts"))));
//          // Timestamp
                        bbattributes.add(new BlackboardAttribute(agentBundleIdAttribute, moduleName, resultSet.getString("bundle")));
                        bbattributes.add(new BlackboardAttribute(agentNameAttribute, moduleName, resultSet.getString("agent_name")));
                        bbattributes.add(new BlackboardAttribute(dataUrlAttribute, moduleName, resultSet.getString("data_url")));
                        bbattributes.add(new BlackboardAttribute(senderNameAttribute, moduleName, resultSet.getString("sender_name")));
                        bbattributes.add(new BlackboardAttribute(senderAddressAttribute, moduleName, resultSet.getString("sender_add")));
                        bbattributes.add(new BlackboardAttribute(typeNumberAttribute, moduleName, resultSet.getInt("type_num")));
                        bbattributes.add(new BlackboardAttribute(originTitleAttribute, moduleName, resultSet.getString("o_title")));
                        bbattributes.add(new BlackboardAttribute(originUrlAttribute, moduleName, resultSet.getString("o_url")));
                        bbattributes.add(new BlackboardAttribute(originAliasAttribute, moduleName, resultSet.getString("o_alias")));
                        
                        newArtifacts.add(createArtifactWithAttributes(customArtifactType, absFile, bbattributes));

                        if (context.dataSourceIngestIsCancelled()) {
                            logger.log(Level.INFO, "Cancelled netusage artifact creation."); //NON-NLS
                            return;
                        }

                    }
                }  catch (SQLException | TskCoreException ex) {
                    logger.log(Level.SEVERE, "Error while trying to read into a sqlite db.", ex);//NON-NLS
                }
            }
        }
        
        if (!context.dataSourceIngestIsCancelled()) {
            postArtifacts(newArtifacts);
        }
    }
    
    private long getHfsDate(Float numberOfSeconds) {

        Calendar newYearsEve = Calendar.getInstance();
        newYearsEve.set(1904, 1, 1, 0, 0, 0);

        Calendar newYearsDay = Calendar.getInstance();
        newYearsDay.setTimeInMillis(newYearsEve.getTimeInMillis());
        if (numberOfSeconds > 0xFFFFFFFF) {
            int numOfSeconds = Math.round(numberOfSeconds) & 0xFFFFFFFF;
            newYearsDay.add(Calendar.SECOND, 60);
        } else {
            newYearsDay.add(Calendar.SECOND, Math.round(numberOfSeconds));
        }
        
        SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss z");
        Long hfsDate = Long.valueOf(0);
        String ddate = newYearsDay.getTime().toString();
        try {
            Date newDate = dateFormat.parse(newYearsDay.getTime().toString());
            hfsDate = newDate.getTime() / 1000;
        } catch (ParseException ex) {
          // catching error and displaying date that could not be parsed
          // we set the timestamp to 0 and continue on processing
            logger.log(Level.WARNING, String.format("Failed to parse date/time %s Installed Program.", numberOfSeconds), ex); //NON-NLS
        }
        
        return hfsDate;
    }

    private long getMacAbsTime(Float numberOfSeconds) {

        Float numOfSeconds = Float.valueOf(numberOfSeconds);
        Calendar newYearsEve = Calendar.getInstance();
        Calendar newYearsDay = Calendar.getInstance();
        
        if (numberOfSeconds == Float.valueOf("-63114076800")) {
            newYearsEve.set(1, 1, 1, 0, 0, 0);
        } else if (Math.abs(numberOfSeconds) > 0xFFFFFFFF) {
            newYearsEve.set(2001, 1, 1, 0, 0, 0);
//            newYearsDay.setTimeInSeconds(newYearsEve.getTimeInSeconds());
            newYearsDay.setTimeInMillis(newYearsEve.getTimeInMillis());
            newYearsDay.add(Calendar.SECOND, Math.round(numberOfSeconds)/100);
        } else {
            newYearsEve.set(2001, 1, 1, 0, 0, 0);
            newYearsDay.setTimeInMillis(newYearsEve.getTimeInMillis());
            newYearsDay.add(Calendar.SECOND, Math.round(numberOfSeconds));
        }
        
        SimpleDateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss z");
        Long macAbsDate = Long.valueOf(0);
        String ddate = newYearsDay.getTime().toString();
        try {
            Date newDate = dateFormat.parse(newYearsDay.getTime().toString());
            macAbsDate = newDate.getTime() / 1000;
        } catch (ParseException ex) {
          // catching error and displaying date that could not be parsed
          // we set the timestamp to 0 and continue on processing
            logger.log(Level.WARNING, String.format("Failed to parse date/time %s Installed Program.", numberOfSeconds), ex); //NON-NLS
        }

        logger.log(Level.WARNING, String.format("Failed to parse date/time %s Installed Program.", numberOfSeconds)); //NON-NLS
        
        return macAbsDate;
    }

    private String getUsernameFromPath(String parentPath, String sqliteFileLocation) {
        
        String newPath = parentPath.replace(sqliteFileLocation + '/', "");
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

    
}
