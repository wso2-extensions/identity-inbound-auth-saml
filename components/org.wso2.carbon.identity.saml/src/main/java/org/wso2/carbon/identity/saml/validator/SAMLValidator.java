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

import org.wso2.carbon.identity.gateway.common.model.sp.RequestValidatorConfig;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.gateway.handler.validator.AbstractRequestValidator;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.exception.SAMLRequestValidatorException;
import org.wso2.carbon.identity.saml.exception.SAMLRuntimeException;
import org.wso2.carbon.identity.saml.model.SAMLValidatorConfig;
import org.wso2.carbon.identity.saml.request.SAMLRequest;
import org.wso2.carbon.identity.saml.util.SAMLSSOConstants;

public abstract class SAMLValidator extends AbstractRequestValidator {

    public void initSAMLMessageContext(AuthenticationContext authenticationContext) {
        SAMLMessageContext samlMessageContext = new SAMLMessageContext((SAMLRequest) authenticationContext
                .getIdentityRequest(), null);
        authenticationContext.addParameter(SAMLSSOConstants.SAMLContext, samlMessageContext);
    }

    @Override
    public abstract GatewayHandlerResponse validate(AuthenticationContext authenticationContext)
            throws SAMLRequestValidatorException;

    @Override
    protected String getValidatorType() {
        return "SAML";
    }

    protected void updateValidatorConfig(RequestValidatorConfig validatorConfig, AuthenticationContext
            authenticationContext) {
        SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext
                .getParameter(SAMLSSOConstants.SAMLContext);
        SAMLValidatorConfig samlValidatorConfig = new SAMLValidatorConfig(validatorConfig);
        messageContext.setSamlValidatorConfig(samlValidatorConfig);
    }

    protected boolean issuerValidate(AuthenticationContext authenticationContext) throws SAMLRequestValidatorException {
        if (authenticationContext.getServiceProvider() == null) {
            SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext
                    .getParameter(SAMLSSOConstants.SAMLContext);
            messageContext.setValid(false);
            String message = "A Service Provider with the Issuer '" + authenticationContext.getUniqueId() + "' is not "
                             +
                             "registered. Service Provider should be registered in " + "advance";
            throw new SAMLRuntimeException(message);
        }
        return true;
    }
}
