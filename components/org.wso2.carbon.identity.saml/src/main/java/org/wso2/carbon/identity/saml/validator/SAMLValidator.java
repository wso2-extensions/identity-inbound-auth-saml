/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
import org.wso2.carbon.identity.gateway.processor.FrameworkHandlerResponse;
import org.wso2.carbon.identity.gateway.processor.handler.request.AbstractRequestValidator;
import org.wso2.carbon.identity.gateway.processor.handler.request.RequestValidatorException;
import org.wso2.carbon.identity.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.request.SAMLRequest;
import org.wso2.carbon.identity.saml.wrapper.SAMLValidatorConfig;

public abstract class SAMLValidator extends AbstractRequestValidator {

    @Override
    public FrameworkHandlerResponse validate(AuthenticationContext authenticationContext) throws
                                                                                          RequestValidatorException {
        SAMLMessageContext samlMessageContext = new SAMLMessageContext((SAMLRequest) authenticationContext
                .getIdentityRequest(), null);
        authenticationContext.addParameter(SAMLSSOConstants.SAMLContext, samlMessageContext);
        return FrameworkHandlerResponse.CONTINUE;
    }

    @Override
    protected String getValidatorType() {
        return "SAML";
    }

    protected void updateValidatorConfig(RequestValidatorConfig validatorConfig, AuthenticationContext
            authenticationContext) throws
                                   RequestValidatorException {
        SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext
                .getParameter(SAMLSSOConstants.SAMLContext);
        SAMLValidatorConfig samlValidatorConfig = new SAMLValidatorConfig(validatorConfig);
        messageContext.setSamlValidatorConfig(samlValidatorConfig);
    }
}
