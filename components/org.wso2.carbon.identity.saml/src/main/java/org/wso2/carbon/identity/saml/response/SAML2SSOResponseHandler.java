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
import org.apache.commons.lang.math.NumberUtils;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.gateway.api.exception.GatewayException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayRuntimeException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayServerException;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.exception.AuthenticationFailure;
import org.wso2.carbon.identity.gateway.exception.ServiceProviderIdNotSetException;
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.gateway.handler.response.AbstractResponseHandler;
import org.wso2.carbon.identity.gateway.model.User;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.saml.bean.SAML2SSOContext;
import org.wso2.carbon.identity.saml.exception.InvalidSPEntityIdException;
import org.wso2.carbon.identity.saml.exception.SAML2SSORequestValidationException;
import org.wso2.carbon.identity.saml.exception.SAML2SSOResponseBuilderException;
import org.wso2.carbon.identity.saml.exception.SAML2SSORuntimeException;
import org.wso2.carbon.identity.saml.exception.SAML2SSOServerException;
import org.wso2.carbon.identity.saml.model.ResponseBuilderConfig;
import org.wso2.carbon.identity.saml.request.SAML2SSORequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * SAML2 SSO Response Handler.
 */
public class SAML2SSOResponseHandler extends AbstractResponseHandler {

    private static Logger logger = LoggerFactory.getLogger(SAMLResponseBuilder.class);

    public String getValidatorType() {
        return SAML2AuthConstants.SAML2_SSO_TYPE;
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
    public GatewayHandlerResponse buildResponse(AuthenticationContext context) throws SAML2SSOResponseBuilderException {

        decorateResponseConfigWithSAML2(context);

        SAML2SSOResponse.SAML2SSOResponseBuilder builder =
                new SAML2SSOResponse.SAML2SSOResponseBuilder(context);
        GatewayHandlerResponse response = new GatewayHandlerResponse(GatewayHandlerResponse.Status.REDIRECT, builder);

        SAML2SSOContext saml2SSOContext = (SAML2SSOContext) context.getParameter(SAML2AuthConstants.SAML_CONTEXT);
        ResponseBuilderConfig config = saml2SSOContext.getResponseBuilderConfig();

        User subjectUser;
        Claim subjectClaim = null;
        try {
            subjectUser = context.getSubjectUser();
            if (subjectUser == null) {
                subjectClaim = context.getSubjectClaim();
                if (subjectClaim == null) {
                    SAML2SSOResponseBuilderException ex =
                            new SAML2SSOResponseBuilderException(StatusCode.RESPONDER_URI,
                                                                 "Cannot find SAML2 subject.");
                    ex.setInResponseTo(saml2SSOContext.getId());
                    ex.setAcsUrl(saml2SSOContext.getAssertionConsumerURL());
                    throw ex;
                }
            }
        } catch (GatewayServerException e) {
            SAML2SSOResponseBuilderException ex =
                    new SAML2SSOResponseBuilderException(StatusCode.RESPONDER_URI, e.getMessage(), e);
            ex.setInResponseTo(saml2SSOContext.getId());
            ex.setAcsUrl(saml2SSOContext.getAssertionConsumerURL());
            throw ex;
        }
        String subject = subjectUser != null ? subjectUser.getUserIdentifier() : subjectClaim.getValue();
        Set<Claim> claims = getAttributes(saml2SSOContext, config, context);

        SAMLResponseBuilder samlResponseBuilder = new SAMLResponseBuilder();
        Response samlResponse = samlResponseBuilder.buildSAMLResponse(subject, claims, saml2SSOContext, config,
                                                                      context);
        builder.setResponse(samlResponse);

        String respString = SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlResponse));
        builder.setRespString(respString);

        builder.setAcsUrl(saml2SSOContext.getAssertionConsumerURL());
        if (StringUtils.isNotBlank(saml2SSOContext.getRelayState())) {
            builder.setRelayState(saml2SSOContext.getRelayState());
        }

        addSessionKey(builder, context);

        return response;
    }

    @Override
    public GatewayHandlerResponse buildErrorResponse(AuthenticationContext context, GatewayException e) {

        if (!(e instanceof InvalidSPEntityIdException)) {
            decorateResponseConfigWithSAML2(context);
        }

        SAML2SSOResponse.SAML2SSOResponseBuilder builder =
                new SAML2SSOResponse.SAML2SSOResponseBuilder(context);
        GatewayHandlerResponse response = new GatewayHandlerResponse(GatewayHandlerResponse.Status.REDIRECT, builder);

        SAMLResponseBuilder samlResponseBuilder = new SAMLResponseBuilder();
        Response samlResponse;
        if (e instanceof SAML2SSORequestValidationException) {
            SAML2SSORequestValidationException e2 = ((SAML2SSORequestValidationException) e);
            samlResponse = samlResponseBuilder.buildErrorResponse(e2.getInResponseTo(), e2.getErrorCode(),
                                                                  e2.getMessage(), e2.getAcsUrl());
            builder.setAcsUrl(e2.getAcsUrl());
        } else if (e instanceof AuthenticationFailure) {
            AuthenticationFailure e2 = (AuthenticationFailure) e;
            SAML2SSOContext saml2SSOContext = (SAML2SSOContext) context.getParameter(SAML2AuthConstants.SAML_CONTEXT);
            List<String> statusCodes = new ArrayList();
            if (AuthenticationFailure.AuthnStatus.INVALID_CREDENTIAL.equals(e2.getErrorCode())) {
                statusCodes.add(StatusCode.AUTHN_FAILED_URI);
                statusCodes.add(StatusCode.RESPONDER_URI);
            } else if (AuthenticationFailure.AuthnStatus.NO_PASSIVE.equals(e2.getErrorCode())) {
                statusCodes.add(StatusCode.NO_PASSIVE_URI);
                statusCodes.add(StatusCode.RESPONDER_URI);
            } else {
                statusCodes.add(StatusCode.RESPONDER_URI);
            }
            samlResponse = samlResponseBuilder.buildErrorResponse(saml2SSOContext.getId(), statusCodes,
                                                                  e.getMessage(),
                                                                  saml2SSOContext.getAssertionConsumerURL());
        } else {
            SAML2SSOServerException e2;
            if (e instanceof SAML2SSOServerException) {
                e2 = ((SAML2SSOServerException) e);
            } else {
                throw new SAML2SSORuntimeException("Exception object not a SAML2SSOServerException.");
            }
            e2 = ((SAML2SSOServerException) e);
            samlResponse = samlResponseBuilder.buildErrorResponse(e2.getInResponseTo(), e2.getErrorCode(),
                                                                  "Server Error", e2.getAcsUrl());
            builder.setAcsUrl(e2.getAcsUrl());
        }
        builder.setResponse(samlResponse);
        builder.setRespString(SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlResponse)));

        return response;
    }

    @Override
    public GatewayHandlerResponse buildErrorResponse(AuthenticationContext context, GatewayRuntimeException e) {

        if (!(e instanceof ServiceProviderIdNotSetException)) {
            decorateResponseConfigWithSAML2(context);
        }

        SAML2SSOResponse.SAML2SSOResponseBuilder builder =
                new SAML2SSOResponse.SAML2SSOResponseBuilder(context);
        GatewayHandlerResponse response = new GatewayHandlerResponse(GatewayHandlerResponse.Status.REDIRECT, builder);

        SAMLResponseBuilder samlResponseBuilder = new SAMLResponseBuilder();
        SAML2SSORuntimeException e1 = null;
        if (e instanceof SAML2SSORuntimeException) {
            e1 = ((SAML2SSORuntimeException) e);
        } else {
            throw new SAML2SSORuntimeException("Exception object not a SAML2SSORuntimeException.");
        }
        Response samlResponse;
        if (StatusCode.REQUESTER_URI.equals(e1.getErrorCode())) {
            samlResponse = samlResponseBuilder.buildErrorResponse(e1.getInResponseTo(), e1.getErrorCode(),
                                                                  e1.getMessage(), e1.getAcsUrl());
        } else {
            samlResponse = samlResponseBuilder.buildErrorResponse(e1.getInResponseTo(), e1.getErrorCode(),
                                                                  "Server Error", e1.getAcsUrl());
        }
        builder.setResponse(samlResponse);
        builder.setRespString(SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlResponse)));
        builder.setAcsUrl(e1.getAcsUrl());

        return response;
    }

    protected void decorateResponseConfigWithSAML2(AuthenticationContext authenticationContext) {

        SAML2SSOContext saml2SSOContext = (SAML2SSOContext) authenticationContext
                .getParameter(SAML2AuthConstants.SAML_CONTEXT);

        org.wso2.carbon.identity.gateway.common.model.sp.ResponseBuilderConfig responseBuilderConfigs =
                getResponseBuilderConfigs(authenticationContext);

        ResponseBuilderConfig responseBuilderConfig = new ResponseBuilderConfig(responseBuilderConfigs);
        saml2SSOContext.setResponseBuilderConfig(responseBuilderConfig);
    }

    protected Set<Claim> getAttributes(SAML2SSOContext saml2SSOContext, ResponseBuilderConfig responseBuilderConfig,
                                       AuthenticationContext context) {

        int requestedIndex = saml2SSOContext.getAttributeConsumingServiceIndex();
        String configuredIndex = responseBuilderConfig.getAttributeConsumingServiceIndex();
        if ((StringUtils.isNotBlank(configuredIndex) && !NumberUtils.isNumber(configuredIndex)) || StringUtils
                .isEmpty(configuredIndex)) {
            if (logger.isDebugEnabled()) {
                logger.debug("Invalid AttributeConsumingServiceIndex configured: " + configuredIndex);
            }
            return Collections.emptySet();
        }

        if (!saml2SSOContext.isIdpInitSSO()) {
            if (requestedIndex == 0) {
                if (!responseBuilderConfig.sendBackClaimsAlways()) {
                    return Collections.emptySet();
                }
            } else {
                if (StringUtils.isNotBlank(configuredIndex) && requestedIndex != Integer.parseInt(configuredIndex)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Invalid AttributeConsumingServiceIndex in request: " + requestedIndex);
                    }
                    return Collections.emptySet();
                }
            }
        } else {
            if (!responseBuilderConfig.sendBackClaimsAlways()) {
                return Collections.emptySet();
            }
        }

        return getAttributes(context);
    }
}
