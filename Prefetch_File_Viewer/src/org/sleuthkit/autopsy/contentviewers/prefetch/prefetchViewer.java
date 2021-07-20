/*
 * Autopsy Forensic Browser
 *
 * Copyright 2018-2019 Basis Technology Corp.
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

package org.sleuthkit.autopsy.contentviewers.prefetch;

import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import org.openide.modules.InstalledFileLocator;
import org.openide.nodes.Node;
import org.openide.util.lookup.ServiceProvider;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.contentviewers.FileViewer;
import org.sleuthkit.autopsy.corecomponentinterfaces.DataContentViewer;
import org.sleuthkit.autopsy.coreutils.ExecUtil;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.SQLiteDBConnect;
import org.sleuthkit.autopsy.datamodel.ContentUtils;
import org.sleuthkit.datamodel.AbstractFile;
/**
 *
 * A content view for prefetch files
 */
@ServiceProvider(service = DataContentViewer.class)
@SuppressWarnings("PMD.SingularField") // UI widgets cause lots of false positives
public class prefetchViewer extends javax.swing.JPanel implements DataContentViewer {

    private static final long serialVersionUID = 1L;
    private static final Logger logger = Logger.getLogger(FileViewer.class.getName());
    private static final String PREFETCH_FILE_EXTENSION = "pf"; //base extension for prefetch file
    private static final String PREFETCH_DIRECTORY = "/prefetch/"; //directory where prefetch files are found
    private static final String MODULE_NAME = "PrefetchViewer"; //NON-NLS
    private static final String BASE_DIR_NAME = "modules";
    private static final String PREFETCH_TOOL_FOLDER = "markmckinnon"; //NON-NLS
    private static final String PREFETCH_TOOL_NAME = "parseprefetch.exe"; //NON-NLS
    private static final String PREFETCH_OUTPUT_FILE_NAME = "Output.txt"; //NON-NLS
    private static final String PREFETCH_ERROR_FILE_NAME = "Error.txt"; //NON-NLS
    private String tempDirPath;
    private String modDirPath;
    private AbstractFile sqliteDbFile;
    private AbstractFile absFile;
    private String actualFileName;

    /**
     * Creates new form prefetchViewer
     */
    public prefetchViewer() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        prefetchInfoTextArea = new javax.swing.JTextArea();

        setName("prefetchInfoJPanel"); // NOI18N

        prefetchInfoTextArea.setColumns(20);
        prefetchInfoTextArea.setRows(5);
        jScrollPane1.setViewportView(prefetchInfoTextArea);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 400, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 289, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    /**
     * Run the prefetch extracting program.
     *
     * @param prefetchExePath path to the prefetch extractor executable.
     * @param tempDirPath path to the temp directory where the prefetch files to be extracted are
     * @param modDirPath path to the module directory to store output
     *
     * @throws FileNotFoundException
     * @throws IOException
     */
    void extractPrefetchFiles(String prefetchExePath, String inputFileName, String outputFileName, String modDirPath) throws FileNotFoundException, IOException {
        final Path outputFilePath = Paths.get(modDirPath, PREFETCH_OUTPUT_FILE_NAME);
        final Path errFilePath = Paths.get(modDirPath, PREFETCH_ERROR_FILE_NAME);
        
        List<String> commandLine = new ArrayList<>();
        commandLine.add(prefetchExePath);
        commandLine.add(inputFileName);  //NON-NLS
        commandLine.add(outputFileName);

        ProcessBuilder processBuilder = new ProcessBuilder(commandLine);
        processBuilder.redirectOutput(outputFilePath.toFile());
        processBuilder.redirectError(errFilePath.toFile());

        ExecUtil.execute(processBuilder);
    }
    

    private String getPathForPrefetchDumper() {
        Path path = Paths.get(BASE_DIR_NAME, PREFETCH_TOOL_FOLDER, PREFETCH_TOOL_NAME);
        File evtxToolFile = InstalledFileLocator.getDefault().locate(path.toString(),
                prefetchViewer.class.getPackage().getName(), false);
        if (evtxToolFile != null) {
            return evtxToolFile.getAbsolutePath();
        }

        return null;
    }

    public void setFile(AbstractFile file) {

        File modDir = new File(modDirPath);
        if (modDir.exists() == false) {
            modDir.mkdirs();
        }
        File tempDir = new File(tempDirPath);
        if (tempDir.exists() == false) {
            tempDir.mkdirs();
        }

        String dbFileName = modDirPath + File.separator + file.getId() + "_" + file.getName() + ".db3";
        String tempFilePath = tempDirPath + File.separator + file.getId() + "_" + file.getName(); 
        File fileName = new File(tempFilePath);
        File aFileName = new File(dbFileName);
        if (!aFileName.exists()) {
            try {
                ContentUtils.writeToFile(file, fileName);
            } catch (IOException ex) {
                logger.log(Level.WARNING, String.format("Unable to write %s to temp directory. File name: %s", file.getName(), tempDirPath), ex); //NON-NLS
            }
            final String prefetchDumper = getPathForPrefetchDumper();
            if (prefetchDumper == null) {
                logger.log(Level.SEVERE, "Error finding parseprefetch.exe program"); //NON-NLS
                return; //If we cannot find the parseprefetch.exe program so we cannot proceed
            }
            try {
               extractPrefetchFiles(prefetchDumper, tempFilePath, actualFileName, modDirPath);
            } catch (IOException ex) {
                logger.log(Level.SEVERE, "Error finding/running parseprefetch.exe program"); //NON-NLS                
            }
        }
        
        String sqlStatement = "select text_col from prefetch_info;"; //NON-NLS

        try (SQLiteDBConnect tempdbconnect = new SQLiteDBConnect("org.sqlite.JDBC", "jdbc:sqlite:" + dbFileName); //NON-NLS
                ResultSet resultSet = tempdbconnect.executeQry(sqlStatement)) {

            String prefetchInfo = "";
            while (resultSet.next()) {
                prefetchInfo = prefetchInfo + resultSet.getString("text_col") + "\n";
            }
            prefetchInfoTextArea.setText(prefetchInfo);
            prefetchInfoTextArea.setCaretPosition(0);

        } catch (SQLException ex) {
            logger.log(Level.WARNING, String.format("Error while trying to read into a sqlite db %s.", dbFileName));//NON-NLS
            logger.log(Level.WARNING, ex.getMessage());
        }
    }

    @Override
    public void setNode(Node node) {
        setFile(absFile);
    }

    @Override
    public String getTitle() {
        return "Prefetch Viewer";
    }

    @Override
    public String getToolTip() {
        return "Prefetch Viewer";
    }

    @Override
    public DataContentViewer createInstance() {
        return new prefetchViewer();
    }

    @Override
    public Component getComponent() {
        return this;
    }

    @Override
    public void resetComponent() {
        prefetchInfoTextArea.setText("");
    }

    @Override
    public boolean isSupported(Node node) {
        AbstractFile file = node.getLookup().lookup(AbstractFile.class);
        if (file == null) {
            return false;
        }
        if (file.getSize() == 0) {
            return false;
        }
        
        String fileExtension = file.getNameExtension();

        if ((file.getNameExtension().toLowerCase().startsWith(PREFETCH_FILE_EXTENSION)) && (file.getParentPath().toLowerCase().endsWith(PREFETCH_DIRECTORY))) {
            absFile = file;
            tempDirPath = Case.getCurrentCase().getTempDirectory() + File.separator + "Prefetch"; //NON-NLS
            modDirPath = Case.getCurrentCase().getModuleDirectory() + File.separator + "Prefetch"; //NON-NLS
            this.actualFileName = modDirPath + File.separator + file.getId() + "_" + file.getName() + ".db3";

            return true;
        }
        
        return false;

    }

    @Override
    public int isPreferred(Node node) {
        return 10;
    }


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea prefetchInfoTextArea;
    // End of variables declaration//GEN-END:variables
}