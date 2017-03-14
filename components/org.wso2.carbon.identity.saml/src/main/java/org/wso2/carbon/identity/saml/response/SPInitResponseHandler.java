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

import org.opensaml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayRuntimeException;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.exception.ResponseHandlerException;
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.saml.bean.MessageContext;
import org.wso2.carbon.identity.saml.request.SPInitRequest;
import org.wso2.carbon.identity.saml.util.Utils;

import java.util.ArrayList;
import java.util.List;

public class SPInitResponseHandler extends SAML2SSOResponseHandler {

    private static Logger log = org.slf4j.LoggerFactory.getLogger(SPInitResponseHandler.class);

    @Override
    public GatewayHandlerResponse buildErrorResponse(AuthenticationContext authenticationContext, GatewayException
            exception) throws ResponseHandlerException {

        super.buildErrorResponse(authenticationContext, exception);

        MessageContext messageContext = (MessageContext) authenticationContext
                .getParameter(SAML2AuthConstants.SAML_CONTEXT);
        SAML2SSOResponse.SAMLResponseBuilder builder;
        GatewayHandlerResponse response = new GatewayHandlerResponse(GatewayHandlerResponse.Status.REDIRECT);

        if (messageContext.isPassive()) { //if passive
            String destination = messageContext.getAssertionConsumerURL();
            List<String> statusCodes = new ArrayList<String>();
            statusCodes.add(StatusCode.NO_PASSIVE_URI);
            statusCodes.add(StatusCode.RESPONDER_URI);
            String errorResponse = null;
            try {
                errorResponse = Utils.SAMLResponseUtil.buildErrorResponse(messageContext.getId(), statusCodes,
                                                                                "Cannot process response from "
                                                                                + "framework Subject in "
                                                                                + "Passive Mode",
                                                                          destination);

                builder = new SuccessResponse.SAMLLoginResponseBuilder(messageContext);
                ((SuccessResponse.SAMLLoginResponseBuilder) builder).setRelayState(messageContext.getRelayState
                        ());
                ((SuccessResponse.SAMLLoginResponseBuilder) builder).setRespString(errorResponse);
                ((SuccessResponse.SAMLLoginResponseBuilder) builder).setAcsUrl(messageContext
                                                                                         .getAssertionConsumerURL());
                response.setGatewayResponseBuilder(builder);
                return response;
            } catch (IdentityException ex) {
                ex.printStackTrace();
            }
        }


        builder = new ErrorResponse.SAMLErrorResponseBuilder(authenticationContext);
        // TODO
        //            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
        //                    (122, SAMLSSOConstants.StatusCodes
        //                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.", null));
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
        // TODO

        //        if (identityMessageContext.getSubject() != null && messageContext.getUser() != null) {
        //            String authenticatedSubjectIdentifier = messageContext.getUser()
        // .getAuthenticatedSubjectIdentifier();
        //            if (authenticatedSubjectIdentifier != null && !authenticatedSubjectIdentifier.equals
        // (messageContext
        //                    .getSubject())) {
        //                String msg = "Provided username does not match with the requested subject";
        //                if (log.isDebugEnabled()) {
        //                    log.debug(msg);
        //                }
        //                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
        //                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
        //                        (messageContext.getId(), SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg,
        //                                serviceProviderConfigs.getDefaultAssertionConsumerUrl()));
        //                return builder;
        //            }
        //        }
        // TODO persist the session

        SAML2SSOResponse.SAMLResponseBuilder builder;
        GatewayHandlerResponse response = new GatewayHandlerResponse(GatewayHandlerResponse.Status.REDIRECT);

        builder = new SuccessResponse.SAMLLoginResponseBuilder(authenticationContext);
        String respString = null;
        try {
            respString = setResponse(authenticationContext, ((SuccessResponse.SAMLLoginResponseBuilder)
                    builder));
            //((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAcsUrl()
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

        if (log.isDebugEnabled()) {
            log.debug("Authentication successfully processed. The SAMLResponse is :" + respString);
        }
        response.setGatewayResponseBuilder(builder);
        return response;
    }


    public boolean canHandle(org.wso2.carbon.identity.common.base.message.MessageContext messageContext) {
        if (messageContext instanceof AuthenticationContext) {
            return ((AuthenticationContext) messageContext)
                    .getInitialAuthenticationRequest() instanceof SPInitRequest;
        }
        return false;
    }


    public String getName() {
        return "SPInitResponseHandler";
    }

    public int getPriority(org.wso2.carbon.identity.common.base.message.MessageContext messageContext) {
        return 15;
    }
}
