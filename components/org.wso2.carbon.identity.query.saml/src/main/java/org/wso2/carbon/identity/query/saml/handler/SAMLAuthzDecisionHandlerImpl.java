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

import org.opensaml.saml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml.saml2.core.DecisionTypeEnumeration;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;

/**
 * This class is used to implement SAMLAuthzDecisionHandler interface to process resources and actions
 */
public class SAMLAuthzDecisionHandlerImpl implements SAMLAuthzDecisionHandler {

    /**
     * Initializer
     */
    public void init() {
    }

    /**
     * This method is a demo implementation of getting action permissions for requested resources
     * @param authzDecisionQuery AuthzDecision request message
     * @return DecisionType Decision taken by IDP on resource
     * @throws  IdentitySAML2QueryException If unable to process
     */
    public DecisionTypeEnumeration getAuthorizationDecision(AuthzDecisionQuery authzDecisionQuery)
            throws IdentitySAML2QueryException{
        return DecisionTypeEnumeration.PERMIT;

    }
}
