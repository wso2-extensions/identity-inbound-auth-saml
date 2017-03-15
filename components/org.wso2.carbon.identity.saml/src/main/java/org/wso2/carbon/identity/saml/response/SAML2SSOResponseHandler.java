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

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.gateway.api.exception.GatewayException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayRuntimeException;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.exception.AuthenticationHandlerException;
import org.wso2.carbon.identity.gateway.exception.ResponseHandlerException;
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.gateway.handler.response.AbstractResponseHandler;
import org.wso2.carbon.identity.saml.bean.MessageContext;
import org.wso2.carbon.identity.saml.exception.SAML2SSORequestValidationException;
import org.wso2.carbon.identity.saml.exception.SAML2SSOResponseBuilderException;
import org.wso2.carbon.identity.saml.exception.SAML2SSORuntimeException;
import org.wso2.carbon.identity.saml.exception.SAML2SSOServerException;
import org.wso2.carbon.identity.saml.model.ResponseBuilderConfig;
import org.wso2.carbon.identity.saml.request.SAML2SSORequest;

/**
 * SAML2 SSO Response Handler.
 */
public class SAML2SSOResponseHandler extends AbstractResponseHandler {

    protected String getValidatorType() {
        // change to "SAML2SSO"
        return "SAML";
    }

    public int getPriority(org.wso2.carbon.identity.common.base.message.MessageContext messageContext) {
        return 16;
    }

    public boolean canHandle(org.wso2.carbon.identity.common.base.message.MessageContext messageContext) {

        if (messageContext instanceof AuthenticationContext) {
            return ((AuthenticationContext) messageContext).getInitialAuthenticationRequest() instanceof
                    SAML2SSORequest;
        }
        return false;
    }

    @Override
    public boolean canHandle(org.wso2.carbon.identity.common.base.message.MessageContext messageContext,
                             GatewayException exception) {

        if (canHandle(messageContext)) {
            if (exception instanceof SAML2SSORequestValidationException ||
                exception instanceof SAML2SSOServerException) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean canHandle(org.wso2.carbon.identity.common.base.message.MessageContext messageContext,
                             GatewayRuntimeException exception) {

        if (canHandle(messageContext)) {
            if (exception instanceof SAML2SSORuntimeException) {
                return true;
            }
        }
        return false;
    }

    @Override
    public GatewayHandlerResponse buildResponse(AuthenticationContext context)
            throws SAML2SSOResponseBuilderException {

        try {
            setSAMLResponseHandlerConfigs(context);
        } catch (AuthenticationHandlerException e) {
            throw new SAML2SSOResponseBuilderException(StatusCode.RESPONDER_URI,
                                                       "Error while getting response handler configurations");
        }

        GatewayHandlerResponse response = new GatewayHandlerResponse(GatewayHandlerResponse.Status.REDIRECT);

        SAML2SSOResponse.SAML2SSOResponseBuilder builder =
                new SAML2SSOResponse.SAML2SSOResponseBuilder(context);

        MessageContext messageContext = (MessageContext) context.getParameter(SAML2AuthConstants.SAML_CONTEXT);
        ResponseBuilderConfig config = messageContext.getResponseBuilderConfig();

        SAMLResponseBuilder samlResponseBuilder = new SAMLResponseBuilder();
        Response samlResponse = samlResponseBuilder.buildSAMLResponse(messageContext, config, context);
        builder.setResponse(samlResponse);

        String respString = SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlResponse));
        builder.setRespString(respString);

        builder.setAcsUrl(messageContext.getAssertionConsumerURL());
        if (StringUtils.isNotBlank(messageContext.getRelayState())) {
            builder.setRelayState(messageContext.getRelayState());
        }

        try {
            addSessionKey(builder, context);
        } catch (ResponseHandlerException e) {
            throw new SAML2SSOResponseBuilderException(StatusCode.RESPONDER_URI, "Server Error", e);
        }

        response.setGatewayResponseBuilder(builder);

        return response;
    }

    @Override
    public GatewayHandlerResponse buildErrorResponse(AuthenticationContext context, GatewayException e)
            throws SAML2SSOResponseBuilderException {

        try {
            setSAMLResponseHandlerConfigs(context);
        } catch (AuthenticationHandlerException e1) {
            throw new SAML2SSOResponseBuilderException(StatusCode.RESPONDER_URI,
                                                       "Error while getting response handler configurations");
        }

        GatewayHandlerResponse response = new GatewayHandlerResponse(GatewayHandlerResponse.Status.REDIRECT);

        SAML2SSOResponse.SAML2SSOResponseBuilder builder =
                new SAML2SSOResponse.SAML2SSOResponseBuilder(context);

        SAMLResponseBuilder samlResponseBuilder = new SAMLResponseBuilder();
        Response samlResponse;
        if (e instanceof SAML2SSORequestValidationException) {
            SAML2SSORequestValidationException e2 = ((SAML2SSORequestValidationException) e);
            samlResponse = samlResponseBuilder.buildErrorResponse(e2.getInResponseTo(), e2.getErrorCode(),
                                                                  e2.getMessage(), e2.getACSUrl());
            builder.setAcsUrl(e2.getACSUrl());
        } else {
            SAML2SSOServerException e2 = ((SAML2SSOServerException) e);
            samlResponse = samlResponseBuilder.buildErrorResponse(e2.getInResponseTo(), e2.getErrorCode(),
                                                                  e2.getMessage(), e2.getACSUrl());
            builder.setAcsUrl(e2.getACSUrl());
        }
        builder.setResponse(samlResponse);
        builder.setRespString(SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlResponse)));

        return response;
    }

    @Override
    public GatewayHandlerResponse buildErrorResponse(AuthenticationContext context, GatewayRuntimeException e)
            throws SAML2SSOResponseBuilderException {

        try {
            setSAMLResponseHandlerConfigs(context);
        } catch (AuthenticationHandlerException e1) {
            throw new SAML2SSOResponseBuilderException(StatusCode.RESPONDER_URI,
                                                       "Error while getting response handler configurations");
        }

        GatewayHandlerResponse response = new GatewayHandlerResponse(GatewayHandlerResponse.Status.REDIRECT);

        SAML2SSOResponse.SAML2SSOResponseBuilder builder =
                new SAML2SSOResponse.SAML2SSOResponseBuilder(context);

        SAMLResponseBuilder samlResponseBuilder = new SAMLResponseBuilder();
        SAML2SSORuntimeException e1 = ((SAML2SSORuntimeException) e);
        Response samlResponse = samlResponseBuilder.buildErrorResponse(e1.getInResponseTo(), e1.getErrorCode(),
                                                                       e1.getMessage(), e1.getACSUrl());
        builder.setResponse(samlResponse);
        builder.setRespString(SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlResponse)));
        builder.setAcsUrl(e1.getACSUrl());

        return response;
    }

    protected void setSAMLResponseHandlerConfigs(AuthenticationContext authenticationContext) throws
                                                                                              AuthenticationHandlerException {
        MessageContext messageContext = (MessageContext) authenticationContext
                .getParameter(SAML2AuthConstants.SAML_CONTEXT);
        org.wso2.carbon.identity.gateway.common.model.sp.ResponseBuilderConfig responseBuilderConfigs = getResponseBuilderConfigs(authenticationContext);
        ResponseBuilderConfig responseBuilderConfig = new ResponseBuilderConfig(responseBuilderConfigs);
        messageContext.setResponseBuilderConfig(responseBuilderConfig);
    }
}
