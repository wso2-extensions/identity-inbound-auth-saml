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
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.Response;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.QueryResponseBuilder;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.handler.SAMLAssertionFinder;

import java.util.ArrayList;
import java.util.List;

/**
 * This class extend from SubjectQueryProcessor and used to process AuthnQuery request messages
 *
 * @see AuthnQuery
 */
public class SAMLAuthnQueryProcessor extends SAMLSubjectQueryProcessor {

    /**
     * Standard logging
     */
    private static final Log log = LogFactory.getLog(SAMLAuthnQueryProcessor.class);

    /**
     * This method is used to process AuthnQuery request message and create response message
     *
     * @param request authnquery request message
     * @return Response response message including one or more assertions
     * @throws  IdentitySAML2QueryException If unable to build assertion or response
     */
    public Response process(RequestAbstractType request) throws IdentitySAML2QueryException {
        Response response = null;
        try {
            String issuer = getIssuer(request);
            String tenantDomain = getTenantDomain(request);
            AuthnQuery authnQuery = (AuthnQuery) request;
            String user = authnQuery.getSubject().getNameID().getValue();
            SAMLSSOServiceProviderDO issuerConfig = getIssuerConfig(issuer);
            String requestedSessionIndex = authnQuery.getSessionIndex();
            RequestedAuthnContext requestedAuthnContext = authnQuery.getRequestedAuthnContext();
            List<AuthnContextClassRef> authnContextClassRefs = requestedAuthnContext.getAuthnContextClassRefs();
            List<Assertion> assertions = new ArrayList<Assertion>();
            List<SAMLAssertionFinder> finders = getFinders();

            for (SAMLAssertionFinder finder : finders) {
                if (requestedSessionIndex != null && requestedSessionIndex.length() > 0) {
                    List<Assertion> collectedAssertions = finder.findBySubjectAndSessionIndex(user, requestedSessionIndex);
                    if(collectedAssertions != null || collectedAssertions.size() > 0) {
                        assertions.addAll(collectedAssertions);
                    }
                }
                if (assertions.size() <= 0 && authnContextClassRefs.size() > 0) {
                    for (AuthnContextClassRef authnContextClassRef : authnContextClassRefs) {
                        List<Assertion> collectedAssertions = finder.findBySubjectAndAuthnContextClassRef(user,
                                authnContextClassRef.getAuthnContextClassRef());
                        if(collectedAssertions != null || collectedAssertions.size() > 0) {
                            assertions.addAll(collectedAssertions);
                        }
                    }
                }
            }
            if (assertions.size() > 0) {
                response = QueryResponseBuilder.build(assertions, issuerConfig, tenantDomain);
                log.debug("Response generated with ID : " + response.getID() + " for the request: " + authnQuery.getID() +
                        " and subject: " + user);
                return response;
            } else {
                return null;
            }
        } catch (NullPointerException e) {
            log.error("AuthnQuery message processing throws NullPointerException for the request: " + request.getID());
            throw new IdentitySAML2QueryException("AuthnQuery message processing throws NullPointerException" +
                    " for the request: " + request.getID());
        }
    }
}
