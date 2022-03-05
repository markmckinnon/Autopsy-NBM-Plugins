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
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.openide.util.NbBundle;
import org.sleuthkit.autopsy.datamodel.ContentUtils;
import java.util.logging.Level;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Arrays;
import org.apache.commons.io.FilenameUtils;
import org.openide.util.NbBundle.Messages;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.NetworkUtils;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.BlackboardAttribute.ATTRIBUTE_TYPE;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.ReadContentInputStream.ReadContentInputStreamException;
import org.sleuthkit.datamodel.Score;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskData;
import org.sleuthkit.datamodel.blackboardutils.WebBrowserArtifactsHelper;

/**
 * Parse Plists
 */
class ParsePlists extends Extract {

    private final Logger logger = Logger.getLogger(this.getClass().getName());
    private Content dataSource;
    private final IngestJobContext context;

    private static final Map<String, String> XML_PLISTS_MAP = ImmutableMap.<String, String>builder()
            .put("InstallHistory.plist", "Library/Receipts")
            .build();

    @Messages({"# {0} - browserName",
        "Progress_Message_Chrome_History=Chrome History Browser {0}",
        "# {0} - browserName",
        "Progress_Message_Chrome_Bookmarks=Chrome Bookmarks Browser {0}",
        "# {0} - browserName",
        "Progress_Message_Chrome_Cookies=Chrome Cookies Browser {0}",
        "# {0} - browserName",
        "Progress_Message_Chrome_Downloads=Chrome Downloads Browser {0}",
        "Progress_Message_Chrome_FormHistory=Chrome Form History",
        "# {0} - browserName",
        "Progress_Message_Chrome_AutoFill=Chrome Auto Fill Browser {0}",
        "# {0} - browserName",
        "Progress_Message_Chrome_Logins=Chrome Logins Browser {0}",
        "Progress_Message_Chrome_Cache=Chrome Cache",})

    ParsePlists(IngestJobContext context) {
        super(NbBundle.getMessage(ParsePlists.class, "ParsePlists"), context);
        this.context = context;
    }

    @Override
    public void process(Content dataSource, DataSourceIngestModuleProgress progressBar) {
        this.dataSource = dataSource;
        dataFound = false;
        long ingestJobId = context.getJobId();

        for (Map.Entry<String, String> browser : XML_PLISTS_MAP.entrySet()) {
            String browserName = browser.getKey();
            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Chrome_History", browserName));
            this.getHistory(browser.getKey(), browser.getValue(), ingestJobId);
            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Chrome_Bookmarks", browserName));
//            this.getBookmark(browser.getKey(), browser.getValue(), ingestJobId);
            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Chrome_Cookies", browserName));
//            this.getCookie(browser.getKey(), browser.getValue(), ingestJobId);
            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Chrome_Logins", browserName));
//            this.getLogins(browser.getKey(), browser.getValue(), ingestJobId);
            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Chrome_AutoFill", browserName));
//            this.getAutofill(browser.getKey(), browser.getValue(), ingestJobId);
            if (context.dataSourceIngestIsCancelled()) {
                return;
            }

            progressBar.progress(NbBundle.getMessage(this.getClass(), "Progress_Message_Chrome_Downloads", browserName));
//            this.getDownload(browser.getKey(), browser.getValue(), ingestJobId);
            if (context.dataSourceIngestIsCancelled()) {
                return;
            }
        }

        progressBar.progress(Bundle.Progress_Message_Chrome_Cache());
        ChromeCacheExtractor chromeCacheExtractor = new ChromeCacheExtractor(dataSource, context, progressBar);
        chromeCacheExtractor.processCaches();
    }

    /**
     * Query for history databases and add artifacts
     *
     * @param browser
     * @param browserLocation
     * @param ingestJobId     The ingest job id.
     */
    private void getHistory(String browser, String browserLocation, long ingestJobId) {
        FileManager fileManager = currentCase.getServices().getFileManager();
        List<AbstractFile> historyFiles;
    }

}
