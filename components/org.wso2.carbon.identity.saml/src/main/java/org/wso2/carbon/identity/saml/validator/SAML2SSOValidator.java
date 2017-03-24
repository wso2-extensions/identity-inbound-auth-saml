/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.saml.validator;

import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.handler.validator.AbstractRequestValidator;
import org.wso2.carbon.identity.gateway.request.ClientAuthenticationRequest;
import org.wso2.carbon.identity.saml.bean.SAML2SSOContext;
import org.wso2.carbon.identity.saml.exception.SAML2SSORequestValidationException;
import org.wso2.carbon.identity.saml.exception.SAML2SSORuntimeException;
import org.wso2.carbon.identity.saml.request.SAML2SSORequest;

import java.util.HashMap;

/**
 * Abstract SAML2 SSO Inbound Request Validator.
 */
public abstract class SAML2SSOValidator extends AbstractRequestValidator {

    protected SAML2SSOContext createInboundMessageContext(AuthenticationContext authenticationContext)
            throws SAML2SSORequestValidationException {

        SAML2SSOContext saml2SSOContext = new SAML2SSOContext(new HashMap());
        ClientAuthenticationRequest request = authenticationContext.getInitialAuthenticationRequest();
        if (request instanceof SAML2SSORequest) {
            saml2SSOContext.setRequest((SAML2SSORequest) request);
        } else {
            throw new SAML2SSORuntimeException("ClientAuthenticationRequest not a SAML2SSORequest.");
        }

        authenticationContext.addParameter(SAML2AuthConstants.SAML_CONTEXT, saml2SSOContext);
        return saml2SSOContext;
    }

    @Override
    public String getValidatorType() {
        return SAML2AuthConstants.SAML2_SSO_TYPE;
    }
}
