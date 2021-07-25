/*
 * Autopsy Forensic Browser
 *
 * Copyright 2020 Basis Technology Corp.
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

import org.openide.util.NbBundle;
import org.openide.util.lookup.ServiceProvider;
import org.sleuthkit.autopsy.coreutils.Version;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.IngestModuleFactoryAdapter;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.modules.vleappanalyzer.Bundle;

/**
 * A factory that creates data source ingest modules that will run cLeapp
 * against logical files and saves the output to module output.
 */
@ServiceProvider(service = IngestModuleFactory.class)
public class VLeappAnalyzerModuleFactory extends IngestModuleFactoryAdapter {

    @NbBundle.Messages({"VLeappAnalyzerModuleFactory.moduleName=Vehicle Leapp (vLEAPP)"})
    static String getModuleName() {
        return Bundle.VLeappAnalyzerModuleFactory_moduleName();
    }

    @Override
    public String getModuleDisplayName() {
        return getModuleName();
    }

    @NbBundle.Messages({"VLeappAnalyzerModuleFactory.moduleDesc=Uses vLEAPP to analyze logical acquisitions of Vehicle Systems."})
    @Override
    public String getModuleDescription() {
        return Bundle.VLeappAnalyzerModuleFactory_moduleDesc();
    }

    @Override
    public String getModuleVersionNumber() {
        return Version.getVersion();
    }

    @Override
    public boolean isDataSourceIngestModuleFactory() {
        return true;
    }

    @Override
    public DataSourceIngestModule createDataSourceIngestModule(IngestModuleIngestJobSettings ingestJobOptions) {
        return new VLeappAnalyzerIngestModule();
    }

}
