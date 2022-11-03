/*
 *
 * Autopsy Forensic Browser
 *
 * Copyright 2012-2021 Basis Technology Corp.
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
import org.openide.util.NbBundle.Messages;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.SQLiteDBConnect;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Account;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper.CommunicationDirection;
import org.sleuthkit.datamodel.blackboardutils.attributes.MessageAttachments;

/**
 * Parse SQLite files
 */
class ParseSQLite extends Extract {

    private final Logger logger = Logger.getLogger(this.getClass().getName());
    private Content dataSource;
    private final IngestJobContext context;
    private final String moduleName;

    Blackboard blkBoard;
    
    private static final Map<String, String> SQLITE_MAP = ImmutableMap.<String, String>builder()
            .put("chat.db", "/Library/Messages")
///            .put("db", "com.apple.notificationcenter/db%")
            .put("netusage.sqlite", "var/networkd")
            .put("com.apple.LaunchServices.QuarantineEventsV2", "Library/Preferences")
            .put("accounts4.sqlite", "/Library/Accounts/")
            .put("accounts3.sqlite", "/Library/Accounts/")
            .put("sqlite.index", "C/com.apple.QuickLook.thumbnailcache")
            .put("db.sqlite", ".DocumentRevisions-V100/db-V1")
////            .put("db.sqlite", "System/Volumes/Data/.DocumentRevisions-V100/db-V1")
            .build();

    private static final Map<String, String> PROCESS_SQLITE_MAP = ImmutableMap.<String, String>builder()
            .put("chat.db", "iMessages")
///            .put("db", "notifications")
            .put("netusage.sqlite", "netusage")
            .put("com.apple.LaunchServices.QuarantineEventsV2", "quarantine")
            .put("accounts4.sqlite", "accounts")
            .put("accounts3.sqlite", "accounts")
            .put("sqlite.index", "quicklook")
            .put("db.sqlite", "documentrevisions")
            .build();

    @Messages({"Progress_Message_Sqlite=Processing Sqlite",
               "ParseSqlite.displayName=ParseSqlite",
               "Progress_Message_IMessage=Processing iMessages",
               "Progress_Message_Notifications=Processing Notifications",
               "Progress_Message_Netusage=Processing Netusage",
               "Progress_Message_Quarantine=Processing Quarantine",
               "Progress_Message_Accounts=Processing Accounts",
               "Progress_Message_Quicklook=Processing Quicklook",
               "Progress_Message_Document_Revisions=Processing Quicklook",
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
                case "accounts":
                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Accounts"));
                    getAccounts(sqliteDb.getKey(), sqliteDb.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "quicklook":
                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Quicklook"));
                    getQuicklook(sqliteDb.getKey(), sqliteDb.getValue(), ingestJobId, tempDirPath);
                    if (context.dataSourceIngestIsCancelled()) {
                        return;
                    }
                    break;
                case "documentrevisions":
                    progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Document_Revisions"));
                    getDocumentRevisions(sqliteDb.getKey(), sqliteDb.getValue(), ingestJobId, tempDirPath);
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

            // Remove this line for production.  Only used for my testing dataset
            if (absFile.getParentPath().contains("surge")) {
               continue;
            }
            
            String userName = getUsernameFromPath(absFile.getParentPath(), sqliteDbFileLocation);

            if (absFile.getName().equals(sqliteDbFileName)) {
                // 978307200 is the number of seconds difference bewteen Unix Epoch time and Apple Absolute Epoch time
                String sqlStatementSelect = "SELECT m.rowid as msg_id, m.handle_id, m.text ,c.chat_identifier as contact, " +
                  " (case when m.is_from_me == 0 then '->' when m.is_from_me == 1 then '<-' end ) as direction, " +
                  " m.account, (m.date/1000000000) + 978307200 as date, (m.date_read/1000000000) + 978307200 as date_read, " +
                  " (m.date_delivered/1000000000) + 978307200 as date_delivered, m.is_from_me, m.is_read, " +
                  " IFNULL(a.filename, 'None') as att_path, IFNULL(a.transfer_name, 'None') as att_name, a.total_bytes as att_size ";  //NON-NLS

                String sqlStatementFrom = " from message as m " +
                  " LEFT JOIN message_attachment_join as ma on ma.message_id = m.rowid " +
                  " LEFT JOIN attachment as a on a.ROWID=ma.attachment_id " +
                  " LEFT JOIN chat_message_join as cmj on cmj.message_id = m.rowid " +
                  " LEFT JOIN chat as c on c.ROWID=cmj.chat_id"; //NON-NLS

                CommunicationArtifactsHelper.MessageReadStatus messageStatus = CommunicationArtifactsHelper.MessageReadStatus.UNKNOWN;
// Add attachment
// Add associated object
                
                String sqliteFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();
                CommunicationArtifactsHelper accountHelper;

                String sqlStatement = "";
                if (checkColumnExists(sqliteFileName, "destination_caller_id", "message")) {
                    sqlStatement = sqlStatementSelect + ", m.destination_caller_id" + sqlStatementFrom;
                } else {
                    sqlStatement = sqlStatementSelect + sqlStatementFrom;
                }
                
                try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sqliteFileName); //NON-NLS
                        ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

                    while (resultSet.next()) {
                        Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
//                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_USER_ID, moduleName, resultSet.getString("account")));
//                        String contact = resultSet.getString("contact");
                        accountHelper = new CommunicationArtifactsHelper(Case.getCurrentCaseThrows().getSleuthkitCase(),
                             moduleName, absFile, Account.Type.MESSAGING_APP);

                        List<BlackboardAttribute> otherAttributes = new ArrayList<>();
                        if (resultSet.getInt("is_read") == 1) {
                            messageStatus = CommunicationArtifactsHelper.MessageReadStatus.READ;
                        } else {
                            messageStatus = CommunicationArtifactsHelper.MessageReadStatus.READ;                            
                        }
                        if (resultSet.getString("direction").equals("<-")) {
                            BlackboardArtifact messageArtifact = accountHelper.addMessage("iMessage", CommunicationDirection.OUTGOING, resultSet.getString("destination_caller_id"),
                                        resultSet.getString("contact"), Long.valueOf(resultSet.getString("date")), messageStatus, null,
                                        resultSet.getString("text"), null, otherAttributes);
                            if (resultSet.getString("att_path") != "None" ) {
                                List<MessageAttachments.FileAttachment> fileAttachments = new ArrayList<>();
                                String fileName = "Users/" + userName + "/" + resultSet.getString("att_path").replace("~", "");
                                fileAttachments.add(new MessageAttachments.FileAttachment(Case.getCurrentCaseThrows().getSleuthkitCase(), dataSource, fileName));
                                MessageAttachments messageAttachments = new MessageAttachments(fileAttachments, new ArrayList<>());
                                accountHelper.addAttachments(messageArtifact, messageAttachments);
                            }
                        } else {
                            BlackboardArtifact messageArtifact = accountHelper.addMessage("iMessage", CommunicationDirection.OUTGOING, resultSet.getString("contact"),
                                        resultSet.getString("destination_caller_id"), Long.valueOf(resultSet.getString("date")), messageStatus, null,
                                        resultSet.getString("text"), null, otherAttributes);
                            if (resultSet.getString("att_path") != "None" ) {
                                List<MessageAttachments.FileAttachment> fileAttachments = new ArrayList<>();
                                fileAttachments.add(new MessageAttachments.FileAttachment(Case.getCurrentCaseThrows().getSleuthkitCase(), dataSource, resultSet.getString("att_path")));
                                MessageAttachments messageAttachments = new MessageAttachments(fileAttachments, new ArrayList<>());
                                accountHelper.addAttachments(messageArtifact, messageAttachments);
                            }
                            
                        }

                        if (context.dataSourceIngestIsCancelled()) {
                            logger.log(Level.INFO, "Cancelled iMessage artifact creation."); //NON-NLS
                            return;
                        }

                    }
                }  catch (SQLException | TskCoreException | NoCurrentCaseException |BlackboardException ex) {
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
        
// Check version of database need to do second query based on version
// Plist in the database so will have to process that as well

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
                            logger.log(Level.INFO, "Cancelled Quarantine artifact creation."); //NON-NLS
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
    
    private void getAccounts(String sqliteDbFileName, String sqliteDbFileLocation, long ingestJobId, String tempDirPath) {
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
        BlackboardAttribute.Type typeAttribute;
        BlackboardAttribute.Type bundleIdAttribute;
        BlackboardAttribute.Type parentIdAttribute;
        BlackboardAttribute.Type uuIdAttribute;
        BlackboardAttribute.Type userAttribute;
         
        try {
            customArtifactType = blkBoard.getOrAddArtifactType("RA_QUARANTINE_EVENTS", "Quarantine Events");
            typeAttribute = blkBoard.getOrAddAttributeType("RA_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Id");
            bundleIdAttribute = blkBoard.getOrAddAttributeType("RA_AGENT_BUNDLE_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Bundle");
            parentIdAttribute = blkBoard.getOrAddAttributeType("RA_PARENT_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent Id");
            uuIdAttribute = blkBoard.getOrAddAttributeType("RA_UUID_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "UUId");
            userAttribute = blkBoard.getOrAddAttributeType("RA_USER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User");
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, "Cannot create artifact/attributes for network usage", ex);//NON-NLS
            return;    
        }

        
        for (AbstractFile absFile : sqliteDbAbsFiles) {
            if (absFile.getName().equals(sqliteDbFileName)) {
                String sqlStatement = "SELECT Z_PK as acc_id, " +
                                      "                (SELECT ZACCOUNTTYPEDESCRIPTION from ZACCOUNTTYPE where ZACCOUNTTYPE.Z_PK=a.ZACCOUNTTYPE) as acc_type, " +
                                      "                IFNULL(a.ZACCOUNTDESCRIPTION, 'None') as acc_name, IFNULL(a.ZUSERNAME, 'None') as acc_user, a.ZDATE as acc_date, " +
                                      "                IFNULL(a.ZPARENTACCOUNT, 'None') as acc_parent_id, a.ZIDENTIFIER as acc_uuid, a.ZOWNINGBUNDLEID as acc_bundle " +
                                      "                FROM ZACCOUNT as a " +
                                      "                WHERE a.Z_ENT = (SELECT Z_ENT FROM Z_PRIMARYKEY WHERE Z_NAME LIKE 'Account')"; //NON-NLS

                String sqliteFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();
                
                try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sqliteFileName); //NON-NLS
                        ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

                    while (resultSet.next()) {
                        Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                        bbattributes.add(new BlackboardAttribute(typeAttribute, moduleName, resultSet.getString("acc_type")));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME, moduleName, resultSet.getString("acc_name")));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_USER_NAME, moduleName, resultSet.getString("acc_user")));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, Long.valueOf(resultSet.getString("ts"))));
                        bbattributes.add(new BlackboardAttribute(uuIdAttribute, moduleName, resultSet.getString("acc_uuid")));
                        bbattributes.add(new BlackboardAttribute(parentIdAttribute, moduleName, resultSet.getString("acc_parent_id")));
                        bbattributes.add(new BlackboardAttribute(bundleIdAttribute, moduleName, resultSet.getString("bundle")));
                        bbattributes.add(new BlackboardAttribute(userAttribute, moduleName, getUsernameFromPath(absFile.getParentPath(), sqliteDbFileLocation)));
                        
                        newArtifacts.add(createArtifactWithAttributes(customArtifactType, absFile, bbattributes));

                        if (context.dataSourceIngestIsCancelled()) {
                            logger.log(Level.INFO, "Cancelled Accounts artifact creation."); //NON-NLS
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

    private void getQuicklook(String sqliteDbFileName, String sqliteDbFileLocation, long ingestJobId, String tempDirPath) {
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
        BlackboardAttribute.Type typeAttribute;
        BlackboardAttribute.Type bundleIdAttribute;
        BlackboardAttribute.Type parentIdAttribute;
        BlackboardAttribute.Type uuIdAttribute;
        BlackboardAttribute.Type userAttribute;
         
        try {
            customArtifactType = blkBoard.getOrAddArtifactType("RA_QUARANTINE_EVENTS", "Quarantine Events");
            typeAttribute = blkBoard.getOrAddAttributeType("RA_TYPE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Event Id");
            bundleIdAttribute = blkBoard.getOrAddAttributeType("RA_AGENT_BUNDLE_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Bundle");
            parentIdAttribute = blkBoard.getOrAddAttributeType("RA_PARENT_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Parent Id");
            uuIdAttribute = blkBoard.getOrAddAttributeType("RA_UUID_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "UUId");
            userAttribute = blkBoard.getOrAddAttributeType("RA_USER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "User");
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, "Cannot create artifact/attributes for network usage", ex);//NON-NLS
            return;    
        }

        
        for (AbstractFile absFile : sqliteDbAbsFiles) {
            if (absFile.getName().equals(sqliteDbFileName)) {
                String sqlStatement = "SELECT Z_PK as acc_id, " +
                                      "                (SELECT ZACCOUNTTYPEDESCRIPTION from ZACCOUNTTYPE where ZACCOUNTTYPE.Z_PK=a.ZACCOUNTTYPE) as acc_type, " +
                                      "                IFNULL(a.ZACCOUNTDESCRIPTION, 'None') as acc_name, IFNULL(a.ZUSERNAME, 'None') as acc_user, a.ZDATE as acc_date, " +
                                      "                IFNULL(a.ZPARENTACCOUNT, 'None') as acc_parent_id, a.ZIDENTIFIER as acc_uuid, a.ZOWNINGBUNDLEID as acc_bundle " +
                                      "                FROM ZACCOUNT as a " +
                                      "                WHERE a.Z_ENT = (SELECT Z_ENT FROM Z_PRIMARYKEY WHERE Z_NAME LIKE 'Account')"; //NON-NLS

                String sqliteFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();
                
                try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sqliteFileName); //NON-NLS
                        ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

                    while (resultSet.next()) {
                        Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                        bbattributes.add(new BlackboardAttribute(typeAttribute, moduleName, resultSet.getString("acc_type")));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_NAME, moduleName, resultSet.getString("acc_name")));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_USER_NAME, moduleName, resultSet.getString("acc_user")));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_DATETIME, moduleName, Long.valueOf(resultSet.getString("ts"))));
                        bbattributes.add(new BlackboardAttribute(uuIdAttribute, moduleName, resultSet.getString("acc_uuid")));
                        bbattributes.add(new BlackboardAttribute(parentIdAttribute, moduleName, resultSet.getString("acc_parent_id")));
                        bbattributes.add(new BlackboardAttribute(bundleIdAttribute, moduleName, resultSet.getString("bundle")));
                        bbattributes.add(new BlackboardAttribute(userAttribute, moduleName, getUsernameFromPath(absFile.getParentPath(), sqliteDbFileLocation)));
                        
                        newArtifacts.add(createArtifactWithAttributes(customArtifactType, absFile, bbattributes));

                        if (context.dataSourceIngestIsCancelled()) {
                            logger.log(Level.INFO, "Cancelled Quicklook artifact creation."); //NON-NLS
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

    private void getDocumentRevisions(String sqliteDbFileName, String sqliteDbFileLocation, long ingestJobId, String tempDirPath) {
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
        BlackboardAttribute.Type inodeNumberAttribute;
        BlackboardAttribute.Type storageIdAttribute;
        BlackboardAttribute.Type fileLastSeenAttribute;
        BlackboardAttribute.Type genLastSeenAttribute;
        BlackboardAttribute.Type genPathAttribute;
         
        try {
            customArtifactType = blkBoard.getOrAddArtifactType("RA_DOCUMENT_REVISIONS", "Document Revisions");
            inodeNumberAttribute = blkBoard.getOrAddAttributeType("RA_INODE_NUMBER", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.LONG, "Inode Number");
            storageIdAttribute = blkBoard.getOrAddAttributeType("RA_STORAGE_ID", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.INTEGER, "Storage Id");
            fileLastSeenAttribute = blkBoard.getOrAddAttributeType("RA_FILE_LAST_SEEN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "File Last Seen (UTC)");
            genLastSeenAttribute = blkBoard.getOrAddAttributeType("RA_GEN_LAST_SEEN", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.DATETIME, "Generation Add Time (UTC)");
            genPathAttribute = blkBoard.getOrAddAttributeType("RA_GENERATION_PATH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Generation Path");            
        } catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, "Cannot create artifact/attributes for network usage", ex);//NON-NLS
            return;    
        }

        
        for (AbstractFile absFile : sqliteDbAbsFiles) {
            if (absFile.getName().equals(sqliteDbFileName) && absFile.getParentPath().contains(sqliteDbFileLocation)) {
                String sqlStatement = "SELECT files.file_inode as inode, generations.generation_storage_id as storage_id, files.file_path as path," +
                                      "       files.file_last_seen as file_last_seen_utc," +
                                      "       generations.generation_add_time as generation_add_time_utc," +
                                      "       generations.generation_path as generation_path" +
                                      "  FROM files inner join generations ON generations.generation_storage_id = files.file_storage_id"; //NON-NLS

                String sqliteFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();
                
                try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + sqliteFileName); //NON-NLS
                        ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

                    while (resultSet.next()) {
                        Collection<BlackboardAttribute> bbattributes = new ArrayList<>();
                        bbattributes.add(new BlackboardAttribute(inodeNumberAttribute, moduleName, Long.valueOf(resultSet.getString("inode"))));
                        bbattributes.add(new BlackboardAttribute(storageIdAttribute, moduleName, resultSet.getInt("storage_id")));
                        bbattributes.add(new BlackboardAttribute(ATTRIBUTE_TYPE.TSK_PATH, moduleName, resultSet.getString("path")));
                        bbattributes.add(new BlackboardAttribute(fileLastSeenAttribute, moduleName, Long.valueOf(resultSet.getString("file_last_seen_utc"))));
                        bbattributes.add(new BlackboardAttribute(genLastSeenAttribute, moduleName, Long.valueOf(resultSet.getString("generation_add_time_utc"))));
                        bbattributes.add(new BlackboardAttribute(genPathAttribute, moduleName, resultSet.getString("generation_path")));
                        
                        newArtifacts.add(createArtifactWithAttributes(customArtifactType, absFile, bbattributes));

                        if (context.dataSourceIngestIsCancelled()) {
                            logger.log(Level.INFO, "Cancelled Document Revision artifact creation."); //NON-NLS
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
            String fName = absFile.getName();
            if (absFile.getName().equals(fileName)) {
    //            String tempFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();
                String tempFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();

                try {
                    ContentUtils.writeToFile(absFile, new File(tempFileName));
                    checkWalShmFiles(fileName, fileLocation, tempDirPath, absFile.getId());
                } catch (IOException ex) {
                    logger.log(Level.WARNING, String.format("Cannot write file to temp directory, file name is %s and file path is %s", fileName, fileLocation), ex); //NON-NLS
                    throw new IOException(String.format("Error getting files for %s in path %s", fileName, fileLocation));
                }
            }
        }
        
        return absFiles;
    }
    
    private boolean checkColumnExists(String dbName, String columnName, String tableName) {
        
        String sqlStatement = "PRAGMA table_info(" + tableName + ");";
        try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + dbName); //NON-NLS
            ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {
                while (resultSet.next()) {
                    if (resultSet.getString("name").toLowerCase().equals(columnName.toLowerCase())) {
                        return true;
                    }            
                }
            }  catch (SQLException  ex) {
                    logger.log(Level.SEVERE, "Error while trying to read into a sqlite db " + dbName, ex);//NON-NLS
            }
    
        return false;
    }

    private void checkWalShmFiles(String fileName, String fileLocation, String tempDirPath, Long fileId) throws TskCoreException, IOException{
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> absFiles = new ArrayList<>();

        try {
            absFiles = fileManager.findFiles(dataSource, fileName + '%', fileLocation); //NON-NLS            
        } catch (TskCoreException ex) {
            logger.log(Level.WARNING, String.format("Error getting files for %s in path %s", fileName, fileLocation), ex); //NON-NLS
            throw new TskCoreException(String.format("Error getting files for %s in path %s", fileName, fileLocation));
        }
        
        for (AbstractFile absFile : absFiles) {
            
            if ((absFile.getName().contains("-wal") || absFile.getName().contains("-shm")) && absFile.getParentPath().contains(fileLocation)) {
    //            String tempFileName = tempDirPath + File.separator + absFile.getId() + "_" + absFile.getName();
                String tempFileName = tempDirPath + File.separator + fileId + "_" + absFile.getName();

                try {
                    ContentUtils.writeToFile(absFile, new File(tempFileName));
                } catch (IOException ex) {
                    logger.log(Level.WARNING, String.format("Cannot write file to temp directory, file name is %s and file path is %s", fileName, fileLocation), ex); //NON-NLS
                    throw new IOException(String.format("Error getting files for %s in path %s", fileName, fileLocation));
                }
            }
        }
        
    }

    
}
