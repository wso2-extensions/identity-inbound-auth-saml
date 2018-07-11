/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.sso.saml.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.sso.saml.dto.SAMLArtifactResolveDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;

/**
 * DAO class used to manipulate SAML artifacts data in the database.
 */
public class SAMLArtifactDAO {

    private static final Log log = LogFactory.getLog(SAMLArtifactDAO.class);

    private static final String ARTIFACT_STORE_SQL = "INSERT INTO IDN_SAML2_ARTIFACT_STORE(SOURCE_ID, " +
            "MESSAGE_HANDLER, AUTHN_REQ_DTO, SESSION_ID, INIT_TIMESTAMP, EXP_TIMESTAMP) VALUES (?, ?, ?, ?, ?, ?)";
    private static final String ASSERTION_RETRIEVE_SQL = "SELECT ID, AUTHN_REQ_DTO, SESSION_ID, INIT_TIMESTAMP, " +
            "EXP_TIMESTAMP FROM IDN_SAML2_ARTIFACT_STORE WHERE SOURCE_ID=? AND MESSAGE_HANDLER=?";
    private static final String ASSERTION_DELETE_SQL = "DELETE FROM IDN_SAML2_ARTIFACT_STORE WHERE ID=?";

    private static final String ID_COLUMN_NAME = "ID";
    private static final String AUTHN_REQ_DTO_COLUMN_NAME = "AUTHN_REQ_DTO";
    private static final String SESSION_ID_COLUMN_NAME = "SESSION_ID";
    private static final String INIT_TIMESTAMP_COLUMN_NAME = "INIT_TIMESTAMP";
    private static final String EXP_TIMESTAMP_COLUMN_NAME = "EXP_TIMESTAMP";

    /**
     * Store SAML artifact in the database.
     *
     * @param artifactResolveDTO SAMLArtifactResolveDTO object with all data.
     */
    public void storeArtifact(SAMLArtifactResolveDTO artifactResolveDTO) {

        try (Connection connection = JDBCPersistenceManager.getInstance().getDBConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(ARTIFACT_STORE_SQL)) {

            preparedStatement.setBytes(1, artifactResolveDTO.getSourceId());
            preparedStatement.setBytes(2, artifactResolveDTO.getMessageHandler());
            setBlobObject(preparedStatement, artifactResolveDTO.getAuthnReqDTO(), 3);
            preparedStatement.setString(4, artifactResolveDTO.getSessionID());
            preparedStatement.setTimestamp(5, new Timestamp(artifactResolveDTO.getInitTimestamp().getMillis()));
            preparedStatement.setTimestamp(6, new Timestamp(artifactResolveDTO.getExpTimestamp().getMillis()));

            preparedStatement.executeUpdate();
            connection.commit();

        } catch (SQLException |IOException e) {
            log.error("Error while storing SAML artifact data: ", e);
        }
    }

    /**
     * Return the SAML response data of a given SAML artifact. Return null otherwise.
     *
     * @param artifactResolveDTO SAMLArtifactResolveDTO object with source ID and message handler.
     * @return SAMLArtifactResolveDTO object with data in the database.
     */
    public SAMLArtifactResolveDTO getSAMLResponse(SAMLArtifactResolveDTO artifactResolveDTO) {

        try (Connection connection = JDBCPersistenceManager.getInstance().getDBConnection();
             PreparedStatement retrievePreparedStatement = connection.prepareStatement(ASSERTION_RETRIEVE_SQL);
             PreparedStatement deletePreparedStatement = connection.prepareStatement(ASSERTION_DELETE_SQL)) {

            retrievePreparedStatement.setBytes(1, artifactResolveDTO.getSourceId());
            retrievePreparedStatement.setBytes(2, artifactResolveDTO.getMessageHandler());

            try (ResultSet resultSet = retrievePreparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    // Extract data from the result set.
                    int id = resultSet.getInt(ID_COLUMN_NAME);
                    artifactResolveDTO.setAuthnReqDTO(
                            (SAMLSSOAuthnReqDTO) getBlobObject(resultSet.getBinaryStream(AUTHN_REQ_DTO_COLUMN_NAME)));
                    artifactResolveDTO.setSessionID(resultSet.getString(SESSION_ID_COLUMN_NAME));
                    artifactResolveDTO.setInitTimestamp(
                            new DateTime(resultSet.getTimestamp(INIT_TIMESTAMP_COLUMN_NAME)));
                    artifactResolveDTO.setExpTimestamp(
                            new DateTime(resultSet.getTimestamp(EXP_TIMESTAMP_COLUMN_NAME)));

                    // Deleting record.
                    deletePreparedStatement.setInt(1, id);
                    deletePreparedStatement.execute();
                }
            } catch (SQLException | IOException | ClassNotFoundException e) {
                log.error("Error while retrieving SAML artifact data. ", e);
            }

            connection.commit();

        } catch (SQLException e) {
            log.error("Error while retrieving SAML artifact data. ", e);
        }
        return artifactResolveDTO;
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
    private void setBlobObject(PreparedStatement prepStmt, Object value, int index) throws SQLException, IOException {
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

    /**
     * Retun java object from input stream. Used to retrieve blob objects from database.
     *
     * @param is Input stream.
     * @return Java object constructed from the input stream.
     * @throws IOException
     * @throws ClassNotFoundException
     */
    private Object getBlobObject(InputStream is) throws IOException, ClassNotFoundException {
        if (is != null) {
            ObjectInput ois = null;
            try {
                ois = new ObjectInputStream(is);
                return ois.readObject();
            } finally {
                if (ois != null) {
                    try {
                        ois.close();
                    } catch (IOException e) {
                        log.error("IOException while trying to close ObjectInputStream.", e);
                    }
                }
            }
        }
        return null;
    }
}
