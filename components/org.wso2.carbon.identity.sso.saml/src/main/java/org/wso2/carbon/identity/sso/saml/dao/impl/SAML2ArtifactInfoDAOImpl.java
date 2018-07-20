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

package org.wso2.carbon.identity.sso.saml.dao.impl;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.wso2.carbon.consent.mgt.core.util.JdbcUtils;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.sso.saml.dao.SAML2ArtifactInfoDAO;
import org.wso2.carbon.identity.sso.saml.dto.SAML2ArtifactInfo;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.exception.ArtifactBindingException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

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
 * Default implementation of SAML2ArtifactInfoDAO.
 */
public class SAML2ArtifactInfoDAOImpl implements SAML2ArtifactInfoDAO {

    @Override
    public void storeArtifactInfo(SAML2ArtifactInfo saml2ArtifactInfo) throws ArtifactBindingException {

        final String ARTIFACT_INFO_STORE_SQL = "INSERT INTO IDN_SAML2_ARTIFACT_STORE(SOURCE_ID, " +
                "MESSAGE_HANDLER, AUTHN_REQ_DTO, SESSION_ID, INIT_TIMESTAMP, EXP_TIMESTAMP, ASSERTION_ID) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?)";
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();

        try {
            jdbcTemplate.executeInsert(ARTIFACT_INFO_STORE_SQL, (preparedStatement -> {
                preparedStatement.setBytes(1, saml2ArtifactInfo.getSourceId());
                preparedStatement.setBytes(2, saml2ArtifactInfo.getMessageHandler());
                try {
                    setBlobObject(preparedStatement, saml2ArtifactInfo.getAuthnReqDTO(), 3);
                } catch (IOException e) {
                    throw new SQLException("Could not set Saml2ArtifactInfo.AuthnReqDTO as a Blob.", e);
                }
                preparedStatement.setString(4, saml2ArtifactInfo.getSessionID());
                preparedStatement.setTimestamp(5, new Timestamp(saml2ArtifactInfo.getInitTimestamp().getMillis()));
                preparedStatement.setTimestamp(6, new Timestamp(saml2ArtifactInfo.getExpTimestamp().getMillis()));
                preparedStatement.setString(7, saml2ArtifactInfo.getAssertionID());
            }), saml2ArtifactInfo, true);
        } catch (DataAccessException e) {
            throw new ArtifactBindingException("Error while storing SAML2 artifact information.");
        }
    }

    @Override
    public SAML2ArtifactInfo getSAMLArtifactInfo(byte[] sourceId, byte[] messageHandler) throws ArtifactBindingException {

        final String ARTIFACT_INFO_RETRIEVE_SQL = "SELECT ID, AUTHN_REQ_DTO, SESSION_ID, INIT_TIMESTAMP, " +
                "EXP_TIMESTAMP FROM IDN_SAML2_ARTIFACT_STORE WHERE SOURCE_ID=? AND MESSAGE_HANDLER=?";
        final String ASSERTION_DELETE_SQL = "DELETE FROM IDN_SAML2_ARTIFACT_STORE WHERE ID=?";
        SAML2ArtifactInfo saml2ArtifactInfo;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();

        try {
            saml2ArtifactInfo = jdbcTemplate.fetchSingleRecord(ARTIFACT_INFO_RETRIEVE_SQL, (resultSet, rowNumber) ->
                    {
                        try {
                            return new SAML2ArtifactInfo(resultSet.getInt(1),
                                    (SAMLSSOAuthnReqDTO) getBlobObject(resultSet.getBinaryStream(2)),
                                    resultSet.getString(3),
                                    new DateTime(resultSet.getTimestamp(4)),
                                    new DateTime(resultSet.getTimestamp(5)));
                        } catch (IOException e) {
                            throw new SQLException("Error in reading the AUTHN_REQ_DTO blob from the database for " +
                                    "sourceId: " + sourceId + ", messageHandler: " + messageHandler, e);
                        } catch (ClassNotFoundException e) {
                            throw new SQLException("Unable to deserialize the object from blob..for " +
                                    "sourceId: " + sourceId + ", messageHandler: " + messageHandler, e);
                        }
                    },
                    preparedStatement -> {
                        preparedStatement.setBytes(1, sourceId);
                        preparedStatement.setBytes(2, messageHandler);

                    });
        } catch (DataAccessException e) {
            throw new ArtifactBindingException("Error while retrieving SAML2 artifact information.", e);
        }

        // Deleting artifact record.
        if (saml2ArtifactInfo != null) {

            try {
                jdbcTemplate.executeUpdate(ASSERTION_DELETE_SQL, preparedStatement ->
                        preparedStatement.setInt(1, saml2ArtifactInfo.getId()));
            } catch (DataAccessException e) {
                throw new ArtifactBindingException("Error while deleting SAML2 artifact information for ID: " +
                        saml2ArtifactInfo.getId(), e);
            }
        }

        return saml2ArtifactInfo;
    }

    @Override
    public Assertion getSAMLAssertion(String assertionId) throws ArtifactBindingException {

        final String ASSERTION_RETRIVE_QUERY =
                "SELECT SAML2_ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_ID=?";

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        Assertion assertion;

        try {
            String assertionString = jdbcTemplate.fetchSingleRecord(ASSERTION_RETRIVE_QUERY, (resultSet, rowNumber) ->
                            resultSet.getString(1), preparedStatement ->
                    preparedStatement.setString(1, assertionId));
            assertion = (Assertion) SAMLSSOUtil.unmarshall(assertionString);
        } catch (DataAccessException e) {
            throw new ArtifactBindingException("Error while retrieving SAML2 artifact information for the SAML2_ID: " +
                    assertionId, e);
        } catch (IdentityException e) {
            throw new ArtifactBindingException("Error while unmarshalling SAML assertion.", e);
        }

        return assertion;
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
                    ois.close();
                }
            }
        }
        return null;
    }
}
