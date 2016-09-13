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
import org.opensaml.saml.saml2.core.Action;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AssertionIDRef;
import org.opensaml.saml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml.saml2.core.DecisionTypeEnumeration;
import org.opensaml.saml.saml2.core.Evidence;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.ActionBuilder;
import org.opensaml.saml.saml2.core.impl.AuthzDecisionStatementBuilder;
import org.opensaml.saml.saml2.core.impl.EvidenceBuilder;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.QueryResponseBuilder;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.handler.SAMLAuthzDecisionHandler;
import org.wso2.carbon.identity.query.saml.handler.SAMLAuthzDecisionHandlerImpl;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;

import java.util.ArrayList;
import java.util.List;

/**
 * This class is used to process AuthzDecisionQuery Request and build response message including relevant assertions
 */
public class SAMLAuthzDecisionProcessor extends SAMLSubjectQueryProcessor {
    /**
     * Standard logging
     */
    private static final Log log = LogFactory.getLog(SAMLAuthzDecisionProcessor.class);

    /**
     * This method is used to process AuthzDecisionQuery request message
     *
     * @param request assertion request message
     * @return Response Collection of zero or more Assertions
     * @throws IdentitySAML2QueryException If occur exception while processing request message
     * @see AuthzDecisionQuery
     */
    @Override
    public Response process(RequestAbstractType request) throws IdentitySAML2QueryException {
        Response response = null;
        try {
            String issuer = getIssuer(request);
            String tenantDomain = getTenantDomain(request);
            AuthzDecisionQuery authzDecisionQuery = (AuthzDecisionQuery) request;
            String resource = authzDecisionQuery.getResource();
            List<Action> requestedActions = authzDecisionQuery.getActions();
            List<Action> permittedActions = new ArrayList<Action>();
            for (Action action : requestedActions) {
                Action tempAction = new ActionBuilder().buildObject();
                tempAction.setAction(action.getAction());
                permittedActions.add(tempAction);
            }
            //assume evidence contains assertionIdRefs only
            Evidence receivedEvidence = authzDecisionQuery.getEvidence();
            Evidence passedEvidence = new EvidenceBuilder().buildObject();
            if (receivedEvidence.getAssertionIDReferences() != null) {
                for (AssertionIDRef in_assertionIDRef : receivedEvidence.getAssertionIDReferences()) {
                    in_assertionIDRef.setParent(null);
                    AssertionIDRef out_assertionIDRef = in_assertionIDRef;
                    passedEvidence.getAssertionIDReferences().add(out_assertionIDRef);
                }
            }

            SAMLSSOServiceProviderDO issuerConfig = getIssuerConfig(issuer);
            SAMLAuthzDecisionHandler samlAuthzDecisionHandler = new SAMLAuthzDecisionHandlerImpl();
            DecisionTypeEnumeration decisionTypeEnumeration = samlAuthzDecisionHandler
                    .getAuthorizationDecision(authzDecisionQuery);
            AuthzDecisionStatement authzDecisionStatement = new AuthzDecisionStatementBuilder().buildObject();
            authzDecisionStatement.setResource(resource);
            authzDecisionStatement.setDecision(decisionTypeEnumeration);
            authzDecisionStatement.getActions().addAll(permittedActions);
            authzDecisionStatement.setEvidence(passedEvidence);

            Assertion assertion = null;
            List<Assertion> assertions = new ArrayList<Assertion>();
            try {
                assertion = SAMLQueryRequestUtil.buildSAMLAssertion(tenantDomain, authzDecisionStatement, issuerConfig);
                assertions.add(assertion);
            } catch (NullPointerException e) {
                log.error("Throws NullPointerException while building assertion for the AuthzDecision request with id: "
                        + authzDecisionQuery.getID(), e);
                throw new IdentitySAML2QueryException("Throws NullPointerException while building assertion for the " +
                        "AuthzDecision request with id: " + authzDecisionQuery.getID(), e);
            }

            try {
                response = QueryResponseBuilder.build(assertions, issuerConfig, tenantDomain);
                log.debug("Response generated with ID : " + response.getID() + " for the request id: "
                        + authzDecisionQuery.getID());
            } catch (NullPointerException e) {
                log.error("Throws NullPointerException while building response for the AuthzDecision request with id: "
                        + authzDecisionQuery.getID(), e);
                throw new IdentitySAML2QueryException("Throws NullPointerException while building response for the " +
                        "AuthzDecision request with id: " + authzDecisionQuery.getID());
            }
        } catch (NullPointerException e) {
            log.error("Throws NullPointerException while processing AuthzDecision request with id: "
                    + request.getID(), e);
            throw new IdentitySAML2QueryException("Throws NullPointerException while processing " +
                    "AuthzDecision request with id: " + request.getID(), e);
        }
        return response;
    }
}
