/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 Inc. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein is strictly forbidden, unless permitted by WSO2 in accordance with
 * the WSO2 Commercial License available at http://wso2.com/licenses. For specific
 * language governing the permissions and limitations under this license,
 * please see the license as well as any agreement you’ve entered into with
 * WSO2 governing the purchase of this software and any associated services.
 */

package org.wso2.carbon.identity.sso.saml.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.SAMLAssertion;
import org.opensaml.saml2.core.Assertion;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * DAO class used to manipulate SAML artifacts data in the database.
 */
public class SAMLArtifactDAO {

    private static final Log log = LogFactory.getLog(SAMLArtifactDAO.class);

    private static final String ARTIFACT_STORE_SQL = "INSERT INTO IDN_SAML2_ARTIFACT_STORE(TYPE_CODE," +
            "ENDPOINT_INDEX, SOURCE_ID, MESSAGE_HANDLER, SAML2_ASSERTION, STATUS) VALUES (?, ?, ?, ?, ?, ?)";
    private static final String ASSERTION_RETRIEVE_SQL = "SELECT ID, SAML2_ASSERTION FROM IDN_SAML2_ARTIFACT_STORE WHERE " +
            "TYPE_CODE=? AND ENDPOINT_INDEX=? AND SOURCE_ID=? AND MESSAGE_HANDLER=?";
    private static final String ASSETION_DELETE_SQL = "DELETE FROM IDN_SAML2_ARTIFACT_STORE WHERE ID=?";

    private static final String SAML2_ASSERTION_COLUMN_NAME = "SAML2_ASSERTION";
    private static final String SAML2_ID_COLUMN_NAME = "ID";

    /**
     * Store SAML artifact in the database.
     *
     * @param typeCode       Type code of the artifact.
     * @param endpointIndex  Endpoint index of the artifact.
     * @param sourceID       Source ID  of the artifact.
     * @param messageHandler Message Handler  of the artifact.
     * @param deflatedSAMLAssertion  Deflated SAML assertion.
     * @param status         Status of the artifact. {INITIATED, RETRIEVED}
     * @throws IdentityException
     */
    public void storeArtifact(byte[] typeCode, byte[] endpointIndex, byte[] sourceID, byte[] messageHandler,
                              String deflatedSAMLAssertion, String status) {

        try (Connection connection = JDBCPersistenceManager.getInstance().getDBConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(ARTIFACT_STORE_SQL)) {

            preparedStatement.setBytes(1, typeCode);
            preparedStatement.setBytes(2, endpointIndex);
            preparedStatement.setBytes(3, sourceID);
            preparedStatement.setBytes(4, messageHandler);
            preparedStatement.setString(5, deflatedSAMLAssertion);
            preparedStatement.setString(6, status);

            preparedStatement.executeUpdate();
            connection.commit();

        } catch (SQLException e) {
            log.error("Error while storing SAML artifact data: ", e);
        }
    }

    /**
     * Return the SAML assertion of a given SAML artifact. Return null otherwise.
     *
     * @param typeCode       Type code of the artifact.
     * @param endpointIndex  Endpoint index of the artifact.
     * @param sourceID       Source ID of the artifact.
     * @param messageHandler Message Handler of the artifact.
     * @return SAML assertion object.
     */
    public Assertion getSAMLAssertion(byte[] typeCode, byte[] endpointIndex, byte[] sourceID,
                                          byte[] messageHandler) throws IdentityException {

        Assertion assertion = null;

        try (Connection connection = JDBCPersistenceManager.getInstance().getDBConnection();
             PreparedStatement retrievePreparedStatement = connection.prepareStatement(ASSERTION_RETRIEVE_SQL);
             PreparedStatement deletePreparedStatement = connection.prepareStatement(ASSETION_DELETE_SQL)) {

            retrievePreparedStatement.setBytes(1, typeCode);
            retrievePreparedStatement.setBytes(2, endpointIndex);
            retrievePreparedStatement.setBytes(3, sourceID);
            retrievePreparedStatement.setBytes(4, messageHandler);

            try (ResultSet resultSet = retrievePreparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    String assertionString = resultSet.getString(SAML2_ASSERTION_COLUMN_NAME);
                    assertion = (Assertion) SAMLSSOUtil.unmarshall(SAMLSSOUtil.decode(assertionString));

                    // Deleting record.
                    int id = resultSet.getInt(SAML2_ID_COLUMN_NAME);
                    deletePreparedStatement.setInt(1, id);
                    deletePreparedStatement.execute();
                }
            } catch (SQLException e) {
                log.error("Error while retrieving SAML artifact data. ", e);
            }
            connection.commit();

        } catch (SQLException e) {
            log.error("Error while retrieving SAML artifact data. ", e);
        }
        return assertion;
    }
}
