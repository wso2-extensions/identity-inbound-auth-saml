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
import org.opensaml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayRuntimeException;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.exception.ResponseHandlerException;
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.saml.bean.MessageContext;
import org.wso2.carbon.identity.saml.model.ResponseBuilderConfig;
import org.wso2.carbon.identity.saml.request.IdPInitRequest;
import org.wso2.carbon.identity.saml.util.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */
public class IdPInitResponseHandler extends SAML2SSOResponseHandler {

    private static Logger log = LoggerFactory.getLogger(SPInitResponseHandler.class);

    @Override
    public GatewayHandlerResponse buildErrorResponse(AuthenticationContext authenticationContext, GatewayException
            exx) throws
                 ResponseHandlerException {

        super.buildErrorResponse(authenticationContext, exx);
        GatewayHandlerResponse response = new GatewayHandlerResponse(GatewayHandlerResponse.Status.REDIRECT);
        MessageContext messageContext = (MessageContext) authenticationContext
                .getParameter(SAML2AuthConstants.SAML_CONTEXT);
        SAML2SSOResponse.SAMLResponseBuilder builder;
        String destination = messageContext.getDestination();
        String errorResp = null;
        //try {
        errorResp = Utils.SAMLResponseUtil.buildErrorResponse(StatusCode.AUTHN_FAILED_URI,
                                                              "User authentication failed", destination);
        /*} catch (IOException e) {
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(authenticationContext);
            response.setGatewayResponseBuilder(builder);
            return response;
        }*/
        builder = new ErrorResponse.SAMLErrorResponseBuilder(messageContext);
        ((ErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(errorResp);
        ((ErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(((IdPInitRequest)
                messageContext.getIdentityRequest()).getAcs());
        response.setGatewayResponseBuilder(builder);
        return response;
    }

    @Override
    public GatewayHandlerResponse buildErrorResponse(AuthenticationContext authenticationContext,
                                                     GatewayRuntimeException exception)
            throws ResponseHandlerException {
        return null;
    }

    @Override
    public GatewayHandlerResponse buildResponse(AuthenticationContext authenticationContext)
            throws ResponseHandlerException {

        super.buildResponse(authenticationContext);
        GatewayHandlerResponse response = new GatewayHandlerResponse(GatewayHandlerResponse.Status.REDIRECT);
        SAML2SSOResponse.SAMLResponseBuilder builder;
        MessageContext messageContext = (MessageContext) authenticationContext
                .getParameter(SAML2AuthConstants.SAML_CONTEXT);


        String relayState = null;
        if (StringUtils.isBlank(relayState)) {
            relayState = messageContext.getRelayState();
        }

        //            builder = authenticate(samlMessageContext, authnResult.isAuthenticated(), authnResult
        //                    .getAuthenticatedAuthenticators(), SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD);

        try {
            builder = authenticate(authenticationContext, true);
        } catch (IdentityException e) {
            builder = new ErrorResponse.SAMLErrorResponseBuilder(authenticationContext);
            // TODO
            //            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
            //                    (122, SAMLSSOConstants.StatusCodes
            //                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.",
            // null));
            response.setGatewayResponseBuilder(builder);
            return response;
        }


        if (builder instanceof SuccessResponse.SAMLLoginResponseBuilder) {
            ((SuccessResponse.SAMLLoginResponseBuilder) builder).setRelayState(relayState);
            ((SuccessResponse.SAMLLoginResponseBuilder) builder).setAcsUrl(messageContext
                                                                                     .getAssertionConsumerURL());

            response.setGatewayResponseBuilder(builder);
            return response;
        } else {
            ((ErrorResponse.SAMLErrorResponseBuilder) builder).setStatus("Error when processing the authentication " +
                                                                          "request!");
            ((ErrorResponse.SAMLErrorResponseBuilder) builder).setMessageLog("Please try login again.");
            ((ErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(messageContext.getResponseBuilderConfig()
                                                                                 .getDefaultAssertionConsumerUrl());
            response.setGatewayResponseBuilder(builder);
            return response;
        }
    }

    public boolean canHandle(org.wso2.carbon.identity.common.base.message.MessageContext messageContext) {
        if (messageContext instanceof AuthenticationContext) {
            return ((AuthenticationContext) messageContext)
                    .getInitialAuthenticationRequest() instanceof IdPInitRequest;
        }
        return false;
    }


    public String getName() {
        return "SAMLIdpInitResponseHandler";
    }

    public int getPriority(org.wso2.carbon.identity.common.base.message.MessageContext messageContext) {
        return 16;
    }

    private SAML2SSOResponse.SAMLResponseBuilder authenticate(AuthenticationContext authenticationContext,
                                                              boolean isAuthenticated) throws
                                                                           IdentityException {

        MessageContext messageContext = (MessageContext) authenticationContext
                .getParameter(SAML2AuthConstants.SAML_CONTEXT);
        ResponseBuilderConfig responseBuilderConfig = messageContext.getResponseBuilderConfig();
        SAML2SSOResponse.SAMLResponseBuilder builder;

        if (isAuthenticated) {
            builder = new SuccessResponse.SAMLLoginResponseBuilder(authenticationContext);
            String respString = setResponse(authenticationContext, ((SuccessResponse.SAMLLoginResponseBuilder)
                    builder));
            if (log.isDebugEnabled()) {
                log.debug("Authentication successfully processed. The SAMLResponse is :" + respString);
            }
            return builder;
        } else {
            List<String> statusCodes = new ArrayList<String>();
            statusCodes.add(StatusCode.AUTHN_FAILED_URI);
            statusCodes.add(StatusCode.RESPONDER_URI);
            if (log.isDebugEnabled()) {
                log.debug("Error processing the authentication request.");
            }
            builder = new ErrorResponse.SAMLErrorResponseBuilder(messageContext);
            ((ErrorResponse.SAMLErrorResponseBuilder) builder)
                    .setErrorResponse(Utils.SAMLResponseUtil.buildErrorResponse
                            (null, statusCodes, "Authentication Failure, invalid username or password.", null));
            ((ErrorResponse.SAMLErrorResponseBuilder) builder)
                    .setAcsUrl(messageContext.getAssertionConsumerURL());
            return builder;
        }
    }
}
