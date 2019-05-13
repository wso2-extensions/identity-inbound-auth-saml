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


import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.Assertion;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;
import org.wso2.carbon.identity.sso.saml.util.DBUtil;

import java.io.IOException;
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

        Assertion assertion;
        if (StringUtils.isNotBlank(id)) {
            assertion = readAssertion(id);
        } else {
            log.error("Assertion ID field is Empty");
            throw new IdentitySAML2QueryException("Assertion ID field is Empty");
        }
        return assertion;
    }

    /**
     * This method is used to search messages from assertion stores by subject of the assertion
     * @param subject This is full qualified subject of the request
     * @return List This returns a list of assertions
     * @throws  IdentitySAML2QueryException If unable to collect assertions from database
     */
    public List<Assertion> findBySubject(String subject) throws IdentitySAML2QueryException {

        List<Assertion> assertions;
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            preparedStatement = connection.prepareStatement(getSelectBySubjectQuery());
            preparedStatement.setString(1, subject);
            resultSet = preparedStatement.executeQuery();
            assertions = extractAssertions(resultSet);
            if (log.isDebugEnabled()){
                log.debug(assertions.size() + " Assertions retrieved from database for the subject:" + subject);
            }
        } catch (SQLException e) {
            log.error("Unable to read assertion from database for the subject: " + subject, e);
            throw new IdentitySAML2QueryException(e.getMessage());
        } catch (IdentitySAML2QueryException e) {
            log.error("unable to unmarshall assertion selected from database for the subject: " + subject, e);
            throw new IdentitySAML2QueryException(e.getMessage());
        } catch (IOException e) {
            throw new IdentitySAML2QueryException("Unable to deserialize the object from blob for " +
                    "the subject: " + subject, e);
        } catch (ClassNotFoundException e) {
            throw new IdentitySAML2QueryException("Error in reading the ASSERTION column blob from the database for " +
                    "the subject: " + subject, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }
        return assertions;
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

        List<Assertion> assertions;
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            preparedStatement = connection.prepareStatement(getSelectBySessionQuery());
            preparedStatement.setString(1, subject);
            preparedStatement.setString(2, sessionIndex);
            resultSet = preparedStatement.executeQuery();
            assertions = extractAssertions(resultSet);
            if (log.isDebugEnabled()){
                log.debug(assertions.size() + "Assertions retrieved from database for the subject: " + subject +
                        " and sessionIndex: " + sessionIndex);
            }
        } catch (SQLException e) {
            log.error("Unable to read assertions from database for the subject: " + subject, e);
            throw new IdentitySAML2QueryException(e.getMessage());
        } catch (NullPointerException e) {
            log.error("Read Assertions from database throws NullPointerException", e);
            throw new IdentitySAML2QueryException("Read Assertions from the database throws NullPointerException for " +
                    "the subject: " + subject + " and sessionindex: " + sessionIndex);
        } catch (IOException e) {
            throw new IdentitySAML2QueryException("Unable to deserialize the object from blob for " +
                    "the subject: " + subject + " and sessionindex: " + sessionIndex, e);
        } catch (ClassNotFoundException e) {
            throw new IdentitySAML2QueryException("Error in reading the ASSERTION column blob from the database for " +
                    "the subject: " + subject + " and sessionindex: " + sessionIndex, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }
        return assertions;
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

        List<Assertion> assertions;
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            preparedStatement = connection.prepareStatement(getSelectByAuthContextQuery());
            preparedStatement.setString(1, subject);
            preparedStatement.setString(2, authnContextClassRef);
            resultSet = preparedStatement.executeQuery();
            assertions = extractAssertions(resultSet);
            if (log.isDebugEnabled()) {
                log.debug(assertions.size() + "Assertions retrieved from database for the subject: " + subject +
                        " and authncontextclassref: " + authnContextClassRef);
            }
            return assertions;
        } catch (SQLException e) {
            log.error("Unable to read assertions from database for the subject: " + subject +
                    " and authncontextclassref: " + authnContextClassRef, e);
            throw new IdentitySAML2QueryException("Unable to read assertions from database for the subject: " + subject +
                    " and authncontextclassref: " + authnContextClassRef);
        } catch (NullPointerException e) {
            log.error("Read Assertions from database throws NullPointerException", e);
            throw new IdentitySAML2QueryException("Read Assertions from the database throws NullPointerException for " +
                    "the subject: " + subject + " and authncontextclassref: " + authnContextClassRef);
        } catch (IOException e) {
            throw new IdentitySAML2QueryException("Unable to deserialize the object from blob for " +
                    "the subject: " + subject + " and authncontextclassref: " + authnContextClassRef, e);
        } catch (ClassNotFoundException e) {
            throw new IdentitySAML2QueryException("Error in reading the ASSERTION column blob from the database for " +
                    "the subject: " + subject + " and authncontextclassref: " + authnContextClassRef, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
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

        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        List<Assertion> assertions;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            preparedStatement = connection.prepareStatement(getSelectByIdQuery());
            preparedStatement.setString(1, id);
            resultSet = preparedStatement.executeQuery();
            assertions = extractAssertions(resultSet);
            if (assertions.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("No Assertion with ID: " + id);
                }
                return null;
            }
        } catch (SQLException e) {
            log.error("Unable to read assertions from databas with ID: " + id, e);
            throw new IdentitySAML2QueryException("Unable to read assertions with id:" + id + " on database ", e);
        } catch (IOException e) {
            throw new IdentitySAML2QueryException("Unable to deserialize the object from blob for " +
                    "assertionId: " + id, e);
        } catch (ClassNotFoundException e) {
            throw new IdentitySAML2QueryException("Error in reading the ASSERTION column blob from the database for " +
                    "assertionId: " + id, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
        }
        return assertions.get(0);
    }

    private String getSelectByIdQuery() {

        String query = "SELECT SAML2_ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_ID=?";
        if (DBUtil.isAssertionDTOPersistenceSupported()) {
            query = "SELECT SAML2_ASSERTION, ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_ID=?";
        }
        return query;
    }

    private String getSelectBySubjectQuery() {

        String query = "SELECT SAML2_ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_SUBJECT =?";
        if (DBUtil.isAssertionDTOPersistenceSupported()) {
            query = "SELECT SAML2_ASSERTION, ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_SUBJECT =?";
        }
        return query;
    }

    private String getSelectBySessionQuery() {

        String query = "SELECT SAML2_ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_SUBJECT =? AND "
            + "SAML2_SESSION_INDEX=? ";
        if (DBUtil.isAssertionDTOPersistenceSupported()) {
            query = "SELECT SAML2_ASSERTION, ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_SUBJECT =? AND "
                    + "SAML2_SESSION_INDEX=? ";
        }
        return query;
    }

    private String getSelectByAuthContextQuery() {

        String query = "SELECT SAML2_ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_SUBJECT =? AND "
            + "SAML2_AUTHN_CONTEXT_CLASS_REF=? ";
        if (DBUtil.isAssertionDTOPersistenceSupported()) {
            query = "SELECT SAML2_ASSERTION, ASSERTION FROM IDN_SAML2_ASSERTION_STORE WHERE SAML2_SUBJECT =? AND "
                    + "SAML2_AUTHN_CONTEXT_CLASS_REF=? ";
        }
        return query;
    }

    private List<Assertion> extractAssertions(ResultSet resultSet) throws SQLException, IOException,
            ClassNotFoundException, IdentitySAML2QueryException {

        List<Assertion> assertions = new ArrayList<>();
        while (resultSet.next()) {
            String assertionString = (String) DBUtil.getBlobObject(resultSet.getBinaryStream("ASSERTION"));
            if (StringUtils.isBlank(assertionString)) {
                assertionString = resultSet.getString("SAML2_ASSERTION");
            }
            assertions.add((Assertion) SAMLQueryRequestUtil.unmarshall(assertionString));
        }
        return assertions;
    }
}
