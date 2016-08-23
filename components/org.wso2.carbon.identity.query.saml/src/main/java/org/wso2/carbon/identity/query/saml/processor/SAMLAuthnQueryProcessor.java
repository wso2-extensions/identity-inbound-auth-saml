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

package org.wso2.carbon.identity.query.saml.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnQuery;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.Response;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.QueryResponseBuilder;
import org.wso2.carbon.identity.query.saml.handler.SAMLAssertionFinder;
import org.wso2.carbon.identity.query.saml.handler.SAMLAssertionFinderImpl;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class extend from SubjectQueryProcessor and used to process AuthnQuery request messages
 *
 * @see AuthnQuery
 */
public class SAMLAuthnQueryProcessor implements SAMLQueryProcessor {

    private final static Log log = LogFactory.getLog(SAMLAuthnQueryProcessor.class);

    /**
     * This method is used to process authnquery request message and create response message
     *
     * @param request authnquery request message
     * @return Response response message including one or more assertions
     */
    public Response process(RequestAbstractType request) {
        Response response = null;
        try {
            AuthnQuery authnQuery = (AuthnQuery) request;
            String issuerFullName = getIssuer(authnQuery.getIssuer());
            String issuer = MultitenantUtils.getTenantAwareUsername(issuerFullName);
            String tenantdomain = MultitenantUtils.getTenantDomain(issuerFullName);
            String user = authnQuery.getSubject().getNameID().getValue() + "@" + tenantdomain;
            SAMLSSOServiceProviderDO issuerConfig = getIssuerConfig(issuer);
            String requestedSessionIndex = authnQuery.getSessionIndex();
            RequestedAuthnContext requestedAuthnContext = authnQuery.getRequestedAuthnContext();
            List<AuthnContextClassRef> authnContextClassRefs = requestedAuthnContext.getAuthnContextClassRefs();
            boolean isAuthStatementsPresent = isAuthStatementPresent(requestedSessionIndex, authnContextClassRefs);
            List<Assertion> assertionsMatchBySubject = new ArrayList<Assertion>();
            Map<String, Assertion> filteredAssertions = new HashMap<String, Assertion>();
            List<Assertion> uniqueAssertions = new ArrayList<Assertion>();
            List<SAMLAssertionFinder> finders = getFinders();
            for (SAMLAssertionFinder finder : finders) {
                List<Assertion> assertions = finder.findBySubject(user);
                if (assertions.size() > 0) {
                    assertionsMatchBySubject.addAll(assertions);
                }
            }
            if (assertionsMatchBySubject.size() > 0) {
                if (isAuthStatementsPresent) {
                    if (requestedSessionIndex != null && requestedSessionIndex.length() > 0) {
                        for (Assertion assertion : assertionsMatchBySubject) {
                            List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
                            for (AuthnStatement authnStatement : authnStatements) {
                                String sessionIndex = authnStatement.getSessionIndex();
                                if (requestedSessionIndex.equals(sessionIndex)) {
                                    filteredAssertions.put(assertion.getID(), assertion);
                                    break;
                                }
                            }

                        }
                    }
                    if (authnContextClassRefs.size() > 0) {
                        for (Assertion assertion : assertionsMatchBySubject) {
                            for (AuthnContextClassRef authnContextClassRef : authnContextClassRefs) {
                                List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
                                for (AuthnStatement authnStatement : authnStatements) {
                                    if (authnStatement.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef().equals(
                                            authnContextClassRef.getAuthnContextClassRef())) {
                                        filteredAssertions.putIfAbsent(assertion.getID(), assertion);
                                        break;
                                    }
                                }

                            }
                        }
                    }

                    if (filteredAssertions.size() > 0) {
                        uniqueAssertions.addAll(filteredAssertions.values());
                    } else {

                        log.error("No assertions Stored for Given SessionIndex or Context");
                        return null;
                    }
                } else {
                    uniqueAssertions.addAll(assertionsMatchBySubject);
                }

            } else {

                log.debug("No Assertions Matched with Subject");
                return null;
            }


            if (uniqueAssertions.size() > 0) {
                try {
                    response = QueryResponseBuilder.build(uniqueAssertions, issuerConfig, tenantdomain);
                    log.debug("Response generated with ID : " + response.getID());
                    return response;
                } catch (IdentityException e) {
                    log.error("Unable to build response for AuthnQuery ", e);
                }

            }
        } catch (Exception ex) {
            log.error("Unable to process AuthnQuery ", ex);
        }
        return response;
    }

    /**
     * This method is used to config assertion finders manually
     *
     * @return List List of assertion finders
     */
    private List<SAMLAssertionFinder> getFinders() {

        List<SAMLAssertionFinder> finders = new ArrayList<SAMLAssertionFinder>();
        SAMLAssertionFinder finder = new SAMLAssertionFinderImpl();
        finder.init();
        finders.add(finder);
        return finders;
    }

    /**
     * Methos to get issuer value
     *
     * @param issuer issuer element of the request
     * @return String issuer name
     */
    protected String getIssuer(Issuer issuer) {

        return issuer.getValue();
    }

    /**
     * This method is used to get issuer information from issuer config
     *
     * @param issuer Name of the issuer
     * @return SAMLSSOServiceProviderDTO issuer information instance
     */
    protected SAMLSSOServiceProviderDO getIssuerConfig(String issuer) {

        try {
            return SAMLQueryRequestUtil.getServiceProviderConfig(issuer);
        } catch (IdentityException e) {
            log.error("Unable to Load Service Provider Config", e);
        }
        return null;
    }

    /**
     * This method used to set flag on authentication context present or not
     *
     * @param sessionIndex          session index value
     * @param authnContextClassRefs list of authentication context class references
     * @return boolean flag set or not
     */
    public boolean isAuthStatementPresent(String sessionIndex, List<AuthnContextClassRef> authnContextClassRefs) {
        return (sessionIndex != null || authnContextClassRefs.size() > 0);
    }

}
