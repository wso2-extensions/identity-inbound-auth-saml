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
import org.wso2.carbon.consent.mgt.core.util.JdbcUtils;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.sso.saml.dao.SAML2ArtifactInfoDAO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLArtifactInfo;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.exception.ArtifactBindingException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;

import static org.wso2.carbon.identity.sso.saml.dao.SQLConstants.ARTIFACT_STORE_SQL;
import static org.wso2.carbon.identity.sso.saml.dao.SQLConstants.ASSERTION_DELETE_SQL;
import static org.wso2.carbon.identity.sso.saml.dao.SQLConstants.ASSERTION_RETRIEVE_SQL;

/**
 * Default implementation of SAML2ArtifactInfoDAO.
 */
public class SAMLArtidactInfoDAOImpl implements SAML2ArtifactInfoDAO {

    @Override
    public void storeArtifactInfo(SAMLArtifactInfo samlArtifactInfo) throws ArtifactBindingException {

        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();

        try {
            jdbcTemplate.executeInsert(ARTIFACT_STORE_SQL, (preparedStatement -> {
                preparedStatement.setBytes(1, samlArtifactInfo.getSourceId());
                preparedStatement.setBytes(2, samlArtifactInfo.getMessageHandler());
                try {
                    setBlobObject(preparedStatement, samlArtifactInfo.getAuthnReqDTO(), 3);
                } catch (IOException e) {
                    throw new SQLException(e);
                }
                preparedStatement.setString(4, samlArtifactInfo.getSessionID());
                preparedStatement.setTimestamp(5, new Timestamp(samlArtifactInfo.getInitTimestamp().getMillis()));
                preparedStatement.setTimestamp(6, new Timestamp(samlArtifactInfo.getExpTimestamp().getMillis()));
            }), samlArtifactInfo, true);
        } catch (DataAccessException e) {
            throw new ArtifactBindingException("Error while storing SAML2 artifact information.");
        }
    }

    @Override
    public SAMLArtifactInfo getSAMLArtifactInfo(byte[] sourceId, byte[] messageHandler) throws ArtifactBindingException {

        SAMLArtifactInfo samlArtifactInfo;
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();

        try {
            samlArtifactInfo = jdbcTemplate.fetchSingleRecord(ASSERTION_RETRIEVE_SQL, (resultSet, rowNumber) ->
                    {
                        try {
                            return new SAMLArtifactInfo(resultSet.getInt(1),
                                    (SAMLSSOAuthnReqDTO) getBlobObject(resultSet.getBinaryStream(2)),
                                    resultSet.getString(3),
                                    new DateTime(resultSet.getTimestamp(4)),
                                    new DateTime(resultSet.getTimestamp(5)));
                        } catch (IOException | ClassNotFoundException e) {
                            throw new SQLException(e);
                        }
                    },
                    preparedStatement -> {
                        preparedStatement.setBytes(1, sourceId);
                        preparedStatement.setBytes(2, messageHandler);

                    });
        } catch (DataAccessException e) {
            throw new ArtifactBindingException("Error while retrieving SAML2 artifact information.");
        }

        // Deleting artifact record.
        if (samlArtifactInfo != null) {

            try {
                jdbcTemplate.executeUpdate(ASSERTION_DELETE_SQL, preparedStatement ->
                        preparedStatement.setInt(1, samlArtifactInfo.getId()));
            } catch (DataAccessException e) {
                throw new ArtifactBindingException("Error while retrieving SAML2 artifact information.");
            }
        }

        return samlArtifactInfo;
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
