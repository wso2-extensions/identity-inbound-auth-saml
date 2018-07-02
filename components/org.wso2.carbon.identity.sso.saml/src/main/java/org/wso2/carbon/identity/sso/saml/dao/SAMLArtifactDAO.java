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
import org.opensaml.saml2.core.Assertion;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * DAO class used to manipulate SAML artifacts data in the database.
 */
public class SAMLArtifactDAO {

    private final static Log log = LogFactory.getLog(SAMLArtifactDAO.class);

    private final static String ARTIFACT_STORE_SQL = "INSERT INTO IDN_SAML2_ARTIFACT_STORE(TYPE_CODE," +
            "ENDPOINT_INDEX, SOURCE_ID, MESSAGE_HANDLER, SAML2_ASSERTION, STATUS) VALUES (?, ?, ?, ?, ?, ?)";

    /**
     * Store SAML artifact in the database.
     *
     * @param typeCode       Type code of the artifact.
     * @param endpointIndex  Endpoint index of the artifact.
     * @param sourceID       Source ID  of the artifact.
     * @param messageHandler Message Handler  of the artifact.
     * @param samlAssertion  Generated SAML assertion.
     * @param status         Status of the artifact. {INITIATED, RETRIEVED}
     * @throws IdentityException
     */
    public void storeArtifact(byte[] typeCode, byte[] endpointIndex, byte[] sourceID, byte[] messageHandler,
                              Assertion samlAssertion, String status) throws IdentityException {

        try (Connection connection = JDBCPersistenceManager.getInstance().getDBConnection();
             PreparedStatement preparedStatement = connection.prepareStatement(ARTIFACT_STORE_SQL)) {

            preparedStatement.setBytes(1, typeCode);
            preparedStatement.setBytes(2, endpointIndex);
            preparedStatement.setBytes(3, sourceID);
            preparedStatement.setBytes(4, messageHandler);
            preparedStatement.setString(5, SAMLSSOUtil.marshall(samlAssertion));
            preparedStatement.setString(6, status);

            preparedStatement.executeUpdate();
            connection.commit();

        } catch (SQLException e) {
            log.error("Error while storing SAML artifact data: ", e);
        }
    }
}
