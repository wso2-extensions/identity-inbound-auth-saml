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
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.gateway.handler.validator.AbstractRequestValidator;
import org.wso2.carbon.identity.saml.bean.MessageContext;
import org.wso2.carbon.identity.saml.exception.SAML2SSOClientException;
import org.wso2.carbon.identity.saml.exception.SAML2SSORequestValidationException;
import org.wso2.carbon.identity.saml.exception.SAML2SSORuntimeException;
import org.wso2.carbon.identity.saml.model.RequestValidatorConfig;
import org.wso2.carbon.identity.saml.request.IdPInitRequest;
import org.wso2.carbon.identity.saml.request.SAML2SSORequest;

import java.util.HashMap;

/**
 * Abstract SAML2 SSO Inbound Request Validator.
 */
public abstract class SAML2SSOValidator extends AbstractRequestValidator {

    protected MessageContext createInboundMessageContext(AuthenticationContext authenticationContext) throws
                                                                                                      SAML2SSORequestValidationException {

        MessageContext messageContext = new MessageContext((SAML2SSORequest) authenticationContext
                .getInitialAuthenticationRequest(), new HashMap());
        authenticationContext.addParameter(SAML2AuthConstants.SAML_CONTEXT, messageContext);
        return messageContext;
    }

    @Override
    public String getValidatorType() {
        // change to "SAML2SSO"
        return "SAML";
    }
}
