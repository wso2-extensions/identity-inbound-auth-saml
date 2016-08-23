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
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.QueryResponseBuilder;
import org.wso2.carbon.identity.query.saml.handler.SAMLAuthzDecisionHandler;
import org.wso2.carbon.identity.query.saml.handler.SAMLAuthzDecisionHandlerImpl;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.List;

public class SAMLAuthzDecisionProcessor extends SAMLSubjectQueryProcessor {

    private static final Log log = LogFactory.getLog(SAMLAttributeQueryProcessor.class);

    @Override
    public Response process(RequestAbstractType request) {

        Response response = null;
        try {
            AuthzDecisionQuery authzDecisionQuery = (AuthzDecisionQuery) request;
            String resource = authzDecisionQuery.getResource();
            String issuerFullName = getIssuer(request.getIssuer());
            String issuer = MultitenantUtils.getTenantAwareUsername(issuerFullName);
            String tenantdomain = MultitenantUtils.getTenantDomain(issuerFullName);
            List<Action> requestedActions = authzDecisionQuery.getActions();
            List<Action> permittedActions = new ArrayList<Action>();
            for (Action action : requestedActions) {
                Action tempAction = new ActionBuilder().buildObject();
                tempAction.setAction(action.getAction());
                permittedActions.add(tempAction);
            }

            Evidence receivedEvidence = authzDecisionQuery.getEvidence();
            Evidence reliedEvidence = new EvidenceBuilder().buildObject();
            if (receivedEvidence.getAssertionIDReferences() != null) {
                for (AssertionIDRef assertionIDRef : receivedEvidence.getAssertionIDReferences()) {
                    AssertionIDRef out_assertionIDRef = assertionIDRef;
                    reliedEvidence.getAssertionIDReferences().add(out_assertionIDRef);
                }
            }

            for (Action action : requestedActions) {
                Action tempAction = new ActionBuilder().buildObject();
                tempAction.setAction(action.getAction());
                permittedActions.add(tempAction);
            }

            SAMLSSOServiceProviderDO issuerConfig = getIssuerConfig(issuer);
            SAMLAuthzDecisionHandler samlAuthzDecisionHandler = new SAMLAuthzDecisionHandlerImpl();
            DecisionTypeEnumeration decisionTypeEnumeration = samlAuthzDecisionHandler.getAuthorizationDecision(authzDecisionQuery);
            AuthzDecisionStatement authzDecisionStatement = new AuthzDecisionStatementBuilder().buildObject();
            authzDecisionStatement.setResource(resource);
            authzDecisionStatement.setDecision(decisionTypeEnumeration);
            authzDecisionStatement.getActions().addAll(permittedActions);
           // authzDecisionStatement.setEvidence(reliedEvidence);

            Assertion assertion = null;
            List<Assertion> assertions = new ArrayList<Assertion>();
            try {
                assertion = SAMLQueryRequestUtil.buildSAMLAssertion(tenantdomain, authzDecisionStatement, issuerConfig);
                assertions.add(assertion);
            } catch (IdentityException e) {
                log.error("Unable to build assertion ", e);
            }

            try {
                response = QueryResponseBuilder.build(assertions, issuerConfig, tenantdomain);
                log.debug("Response generated with ID : " + response.getID());
            } catch (IdentityException e) {
                log.error("Unable to build response for the AttributeQuery ", e);
            }
        } catch (Exception ex) {

            log.error("Unable to process AuthzDecisionQuery", ex);
        }

        return response;
    }


}
