/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.query.saml.handler;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.Assertion;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation class to find assertions dynamically from assertion stores
 *
 * @see SAMLAssertionFinder
 */
public class SAMLAssertionFinderImpl implements SAMLAssertionFinder {
    private static final Log log = LogFactory.getLog(SAMLAssertionFinderImpl.class);

    /**
     * This method is used to initialize handler
     */
    public void init() {

    }

    /**
     * Method to finf assertions from assertion stores by assertion is
     *
     * @param id This is the unique Assertion ID
     * @return Assertion This returns assertion with given assertion id
     */
    public Assertion findByID(String id) {
        Assertion assertion = null;
        if (id.length() > 0) {
            assertion = readAssertion(id);
            return assertion;

        } else {
            log.error("Assertion ID field is Empty");

        }

        return assertion;
    }

    /**
     * This method is used to search messages from assertion stores by subject of the assertion
     *
     * @param subject This is full qualified subject of the request
     * @return List This returns a list of assertions
     */
    public List<Assertion> findBySubject(String subject) {
        List<Assertion> assertions = new ArrayList<Assertion>();
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            preparedStatement = connection.prepareStatement("SELECT SAML2_ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_SUBJECT= ?");
            preparedStatement.setString(1, subject);
            resultSet = preparedStatement.executeQuery();
            int index = 1;
            while (resultSet.next()) {
                String assertionString = resultSet.getString(index);
                try {
                    assertions.add((Assertion) SAMLQueryRequestUtil.unmarshall(assertionString));
                    log.debug("Assertions retrieved from database");
                } catch (Exception e) {
                    log.error("Unable to Retrieve Assertions from ResultSet ", e);
                }
            }
            if (assertions.size() > 0)
                return assertions;
            return null;
        } catch (SQLException e) {
            log.error("Error while reading data", e);
        } finally {
            if (preparedStatement != null) {
                IdentityDatabaseUtil.closeStatement(preparedStatement);
            }
            if (connection != null) {
                IdentityDatabaseUtil.closeConnection(connection);
            }
            if (resultSet != null) {
                IdentityDatabaseUtil.closeResultSet(resultSet);
            }
        }

        return assertions;
    }

    /**
     * This method used to read assertions from assertion store by giving assertion id
     *
     * @param id Uniques assertion id
     * @return Assertion This returns assertion which match with assertion id
     */
    private Assertion readAssertion(String id) {

        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            preparedStatement = connection.prepareStatement("SELECT SAML2_ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_ID= ?");
            preparedStatement.setString(1, id);
            resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                String assertionString = resultSet.getString(1);
                try {
                    Assertion assertion = (Assertion) SAMLQueryRequestUtil.unmarshall(assertionString);
                    log.debug("Assertion is retrieved from database");
                    return assertion;
                } catch (Exception e) {
                    log.error(e);
                }
            }
            return null;
        } catch (SQLException e) {
            log.error("Error while reading data", e);
        } finally {
            if (preparedStatement != null) {
                IdentityDatabaseUtil.closeStatement(preparedStatement);
            }
            if (connection != null) {
                IdentityDatabaseUtil.closeConnection(connection);
            }
            if (resultSet != null) {
                IdentityDatabaseUtil.closeResultSet(resultSet);
            }
        }

        return null;

    }
}
