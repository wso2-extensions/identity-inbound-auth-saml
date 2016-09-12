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
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
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
    /**
     * Standard logging
     */
    private static final Log log = LogFactory.getLog(SAMLAssertionFinderImpl.class);

    /**
     * This method is used to initialize handler
     */
    public void init() {
    }

    /**
     * Method to find assertions from assertion stores by assertion id
     * @param id This is the unique Assertion ID
     * @return Assertion This returns assertion with given assertion id
     * @throws  IdentitySAML2QueryException If request message not contain AssertionId
     */
    public Assertion findByID(String id) throws IdentitySAML2QueryException {
        Assertion assertion = null;
        if (id.length() > 0) {
            assertion = readAssertion(id);
            return assertion;
        } else {
            log.error("Assertion ID field is Empty");
            throw new IdentitySAML2QueryException("Assertion ID field is Empty");
        }

    }

    /**
     * This method is used to search messages from assertion stores by subject of the assertion
     * @param subject This is full qualified subject of the request
     * @return List This returns a list of assertions
     * @throws  IdentitySAML2QueryException If unable to collect assertions from database
     */
    public List<Assertion> findBySubject(String subject) throws IdentitySAML2QueryException {
        List<Assertion> assertions = new ArrayList<Assertion>();
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            String selectBySubjectQuery = "SELECT SAML2_ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_SUBJECT =?";
            preparedStatement = connection.prepareStatement(selectBySubjectQuery);
            preparedStatement.setString(1, subject);
            resultSet = preparedStatement.executeQuery();
            int index = 1;
            while (resultSet.next()) {
                String assertionString = resultSet.getString(index);
                assertions.add((Assertion) SAMLQueryRequestUtil.unmarshall(assertionString));
                log.debug("Assertions retrieved from database for the subject: " + subject);
            }
            if (assertions.size() > 0)
                return assertions;
            return null;
        } catch (SQLException e) {
            log.error("Unable to read assertion from database for the subject: " + subject, e);
            throw new IdentitySAML2QueryException(e.getMessage());
        } catch (IdentitySAML2QueryException e) {
            log.error("unable to unmarshall assertion selected from database for the subject: " + subject, e);
            throw new IdentitySAML2QueryException(e.getMessage());
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
    }

    /**
     * his method is used to collect Assertions according to subject and sessionindex
     * @param subject subject of the assertion
     * @param sessionIndex sessionindex value of the assertion
     * @return List collection of Assertion
     * @throws IdentitySAML2QueryException If unable to collect assertions from database
     */
    public List<Assertion> findBySubjectAndSessionIndex(String subject, String sessionIndex)
            throws IdentitySAML2QueryException {
        List<Assertion> assertions = new ArrayList<Assertion>();
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            String selectBySubjectQuery = "SELECT SAML2_ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_SUBJECT =? " +
                    "AND SAML2_SESSION_INDEX=? ";
            preparedStatement = connection.prepareStatement(selectBySubjectQuery);
            preparedStatement.setString(1, subject);
            preparedStatement.setString(2, sessionIndex);
            resultSet = preparedStatement.executeQuery();
            int index = 1;
            while (resultSet.next()) {
                String assertionString = resultSet.getString(index);
                assertions.add((Assertion) SAMLQueryRequestUtil.unmarshall(assertionString));
                log.debug("Assertion retrieved from database for the subject: " + subject +
                        " and sessionIndex: " + sessionIndex);
            }
            return assertions;
        } catch (SQLException e) {
            log.error("Unable to read assertions from database for the subject: " + subject, e);
            throw new IdentitySAML2QueryException(e.getMessage());
        } catch (NullPointerException e) {
            log.error("Read Assertions from database throws NullPointerException", e);
            throw new IdentitySAML2QueryException("Read Assertions from the database throws NullPointerException for " +
                    "the subject: " + subject + " and sessionindex: " + sessionIndex);
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
    }

    /**
     * This method is used to collect assertions according to subject and AuthnContextClassRef
     * @param subject Subject of the assertion
     * @param authnContextClassRef AuthnContextClassRef value of the assertion
     * @return List Collection of Assertions
     * @throws IdentitySAML2QueryException If unable to collect assertions from database
     */
    public List<Assertion> findBySubjectAndAuthnContextClassRef(String subject, String authnContextClassRef)
            throws IdentitySAML2QueryException {
        List<Assertion> assertions = new ArrayList<Assertion>();
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            String selectBySubjectQuery = "SELECT SAML2_ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_SUBJECT =? " +
                    "AND SAML2_AUTHN_CONTEXT_CLASS_REF=? ";
            preparedStatement = connection.prepareStatement(selectBySubjectQuery);
            preparedStatement.setString(1, subject);
            preparedStatement.setString(2, authnContextClassRef);
            resultSet = preparedStatement.executeQuery();
            int index = 1;
            while (resultSet.next()) {
                String assertionString = resultSet.getString(index);
                assertions.add((Assertion) SAMLQueryRequestUtil.unmarshall(assertionString));
                log.debug("Assertion retrieved from database for the subject: " + subject +
                        " and authncontextclassref: " + authnContextClassRef);
            }
            if (assertions.size() > 0)
                return assertions;
            return null;
        } catch (SQLException e) {
            log.error("Unable to read assertions from database for the subject: " + subject +
                    " and authncontextclassref: " + authnContextClassRef, e);
            throw new IdentitySAML2QueryException("Unable to read assertions from database for the subject: " + subject +
                    " and authncontextclassref: " + authnContextClassRef);
        } catch (NullPointerException e) {
            log.error("Read Assertions from database throws NullPointerException", e);
            throw new IdentitySAML2QueryException("Read Assertions from the database throws NullPointerException for " +
                    "the subject: " + subject + " and authncontextclassref: " + authnContextClassRef);
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
    }

    /**
     * This method used to read assertions from assertion store by giving assertion id
     *
     * @param id Uniques assertion id
     * @return Assertion This returns assertion which match with assertion id
     * @throws  IdentitySAML2QueryException If unable to read assertions from database
     */
    private Assertion readAssertion(String id) throws IdentitySAML2QueryException {
        String selectByIDquery = "SELECT SAML2_ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_ID =?";
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            preparedStatement = connection.prepareStatement(selectByIDquery);
            preparedStatement.setString(1, id);
            resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                String assertionString = resultSet.getString(1);
                try {
                    Assertion assertion = (Assertion) SAMLQueryRequestUtil.unmarshall(assertionString);
                    log.debug("Assertion is retrieved from database with ID: " + id);
                    return assertion;
                } catch (IdentitySAML2QueryException e) {
                    log.error("Unable to unmarshall assertions selected from database with ID: " + id, e);
                    throw new IdentitySAML2QueryException(e.getMessage());
                }
            }
            return null;
        } catch (SQLException e) {
            log.error("Unable to read assertions from databas with ID: " + id, e);
            throw new IdentitySAML2QueryException("Unable to read assertions with id:" + id + " on database ", e);
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
    }
}
