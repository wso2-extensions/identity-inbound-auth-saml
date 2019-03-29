/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class DBUtil {

    private static Log log = LogFactory.getLog(SAMLSSOUtil.class);

    private static final String SAML2_ASSERTION_STORE = "IDN_SAML2_ASSERTION_STORE";
    private static final String ASSERTION = "ASSERTION";

    private static boolean isAssertionDTOPersistenceSupported = false;
    private static boolean isAssertionDTOPersistenceStatusChecked = false;

    private DBUtil() {}

    /**
     * Return if IDN_SAML2_ASSERTION_STORE table has ASSERTION column.
     *
     * @return Existence of ASSERTION column in IDN_SAML2_ASSERTION_STORE
     */
    public static boolean isAssertionDTOPersistenceSupported() {

        if (!isAssertionDTOPersistenceStatusChecked) {
            try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {

                DatabaseMetaData metaData = connection.getMetaData();
                ResultSet rs = metaData.getColumns(null, null, SAML2_ASSERTION_STORE, ASSERTION);
                if (rs.next()) {
                    isAssertionDTOPersistenceSupported = true;
                }
            } catch (SQLException e) {
                log.error("Error in fetching metadata from IDN_SAML2_ASSERTION_STORE database", e);
            }
            isAssertionDTOPersistenceStatusChecked = true;
        }
        return isAssertionDTOPersistenceSupported;
    }

    /**
     * Retun java object from input stream. Used to retrieve blob objects from database.
     *
     * @param is Input stream.
     * @return Java object constructed from the input stream.
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static Object getBlobObject(InputStream is) throws IOException, ClassNotFoundException {

        if (is != null) {
            ObjectInput ois = null;
            try {
                ois = new ObjectInputStream(is);
                return ois.readObject();
            } finally {
                if (ois != null) {
                    ois.close();
                }
            }
        }
        return null;
    }

    /**
     * Serialize an object and set into a prepared statement as a blob.
     *
     * @param prepStmt Prepared statement.
     * @param value    Object to be saved.
     * @param index    Index of the prepared statement.
     * @throws SQLException
     * @throws IOException
     */
    public static void setBlobObject(PreparedStatement prepStmt, Object value, int index) throws SQLException, IOException {
        if (value != null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(value);
            oos.flush();
            oos.close();
            InputStream inputStream = new ByteArrayInputStream(baos.toByteArray());
            prepStmt.setBinaryStream(index, inputStream, inputStream.available());
        } else {
            prepStmt.setBinaryStream(index, null, 0);
        }
    }
}
