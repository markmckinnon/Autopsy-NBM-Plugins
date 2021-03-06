/*
 * Autopsy Forensic Browser
 *
 * Copyright 2018-2018 Basis Technology Corp.
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
package org.sleuthkit.autopsy.contentviewers.eventlogviewer;

/**
 * Provides a system exception for the SQLiteTableReader class. 
 */
public class SQLiteTableReaderException extends Exception {
    
    /**
     * Accepts both a message and a parent exception.
     * 
     * @param msg Message detailing the cause
     * @param parentEx Parent exception
     */
    public SQLiteTableReaderException(String msg, Throwable parentEx) {
        super(msg, parentEx);
    }
    
    /**
     * Accepts only a parent exception.
     * 
     * @param parentEx Parent exception
     */
    public SQLiteTableReaderException(Throwable parentEx) {
        super(parentEx);
    }
}
