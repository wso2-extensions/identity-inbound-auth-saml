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
package org.wso2.carbon.identity.saml.response;

import org.opensaml.saml2.core.Response;
import org.slf4j.Logger;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.gateway.api.exception.GatewayException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayRuntimeException;
import org.wso2.carbon.identity.gateway.common.model.sp.ResponseBuilderConfig;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.exception.AuthenticationHandlerException;
import org.wso2.carbon.identity.gateway.exception.ResponseHandlerException;
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.gateway.handler.response.AbstractResponseHandler;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.exception.SAMLClientException;
import org.wso2.carbon.identity.saml.exception.SAMLRequestValidatorException;
import org.wso2.carbon.identity.saml.exception.SAMLRuntimeException;
import org.wso2.carbon.identity.saml.exception.SAMLServerException;
import org.wso2.carbon.identity.saml.model.SAMLResponseHandlerConfig;
import org.wso2.carbon.identity.saml.util.SAMLSSOConstants;

public abstract class SAMLResponseHandler extends AbstractResponseHandler {

    private static Logger log = org.slf4j.LoggerFactory.getLogger(SAMLSPInitResponseHandler.class);

    @Override
    public GatewayHandlerResponse buildErrorResponse(AuthenticationContext authenticationContext, GatewayException e)
            throws
            ResponseHandlerException {
        try {
            setSAMLResponseHandlerConfigs(authenticationContext);
        } catch (AuthenticationHandlerException ex) {
            throw new ResponseHandlerException("Error while getting response handler configurations");
        }
        return GatewayHandlerResponse.REDIRECT;
    }

    @Override
    public GatewayHandlerResponse buildResponse(AuthenticationContext authenticationContext)
            throws ResponseHandlerException {
        try {
            setSAMLResponseHandlerConfigs(authenticationContext);
        } catch (AuthenticationHandlerException e) {
            throw new ResponseHandlerException("Error while getting response handler configurations");
        }
        return GatewayHandlerResponse.REDIRECT;
    }

    @Override
    public boolean canHandle(MessageContext messageContext, GatewayException exception) {
        if (canHandle(messageContext)) {
            if (exception instanceof SAMLRequestValidatorException || exception instanceof SAMLClientException ||
                exception instanceof SAMLServerException) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean canHandle(MessageContext messageContext, GatewayRuntimeException exception) {
        if (canHandle(messageContext)) {
            if (exception instanceof SAMLRuntimeException) {
                return true;
            }
        }
        return false;
    }

    public String setResponse(AuthenticationContext context, SAMLLoginResponse.SAMLLoginResponseBuilder
            builder) throws IdentityException {

        SAMLMessageContext messageContext = (SAMLMessageContext) context.getParameter(SAMLSSOConstants.SAMLContext);
        SAMLResponseHandlerConfig config = messageContext.getResponseHandlerConfig();

        SAML2SSOResponseBuilder saml2SSOResponseBuilder = new SAML2SSOResponseBuilder();
        Response response = saml2SSOResponseBuilder.buildSAMLResponse(messageContext, config, context);
        builder.setResponse(response);

        String respString = SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(response));
        builder.setRespString(respString);

        builder.setAcsUrl(messageContext.getAssertionConsumerURL());
        builder.setRelayState(messageContext.getRelayState());

        addSessionKey(builder, context);

        return respString;
    }

    protected String getValidatorType() {
        return "SAML";
    }

    protected void setSAMLResponseHandlerConfigs(AuthenticationContext authenticationContext) throws
                                                                                              AuthenticationHandlerException {
        SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext
                .getParameter(SAMLSSOConstants.SAMLContext);
        ResponseBuilderConfig responseBuilderConfigs = getResponseBuilderConfigs(authenticationContext);
        SAMLResponseHandlerConfig samlResponseHandlerConfig = new SAMLResponseHandlerConfig(responseBuilderConfigs);
        messageContext.setResponseHandlerConfig(samlResponseHandlerConfig);
    }
}
