package org.wso2.carbon.identity.saml.response;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.gateway.api.exception.GatewayException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayRuntimeException;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.api.response.GatewayHandlerResponse;
import org.wso2.carbon.identity.gateway.exception.ResponseHandlerException;
import org.wso2.carbon.identity.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.request.SAMLIDPInitRequest;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.saml.wrapper.SAMLResponseHandlerConfig;

import java.util.ArrayList;
import java.util.List;

public class SAMLIdpInitResponseHandler extends SAMLResponseHandler {

    private static Logger log = org.slf4j.LoggerFactory.getLogger(SAMLSPInitResponseHandler.class);

    @Override
    public GatewayHandlerResponse buildErrorResponse(AuthenticationContext authenticationContext, GatewayException
            exx) throws
                 ResponseHandlerException {

        super.buildErrorResponse(authenticationContext, exx);
        GatewayHandlerResponse response = GatewayHandlerResponse.REDIRECT;
        SAMLMessageContext samlMessageContext = (SAMLMessageContext) authenticationContext
                .getParameter(SAMLSSOConstants.SAMLContext);
        SAMLResponse.SAMLResponseBuilder builder;
        String destination = samlMessageContext.getDestination();
        String errorResp = null;
        //try {
        errorResp = SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE,
                                                   "User authentication failed", destination);
        /*} catch (IOException e) {
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(authenticationContext);
            response.setGatewayResponseBuilder(builder);
            return response;
        }*/
        builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(samlMessageContext);
        ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(errorResp);
        ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setStatus(SAMLSSOConstants
                                                                                 .Notification.EXCEPTION_STATUS);
        ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setMessageLog(SAMLSSOConstants
                                                                                     .Notification.EXCEPTION_MESSAGE);
        ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(((SAMLIDPInitRequest)
                samlMessageContext.getIdentityRequest()).getAcs());
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
        GatewayHandlerResponse response = GatewayHandlerResponse.REDIRECT;
        SAMLResponse.SAMLResponseBuilder builder;
        SAMLMessageContext samlMessageContext = (SAMLMessageContext) authenticationContext
                .getParameter(SAMLSSOConstants.SAMLContext);


        String relayState = null;
        if (StringUtils.isBlank(relayState)) {
            relayState = samlMessageContext.getRelayState();
        }

        //            builder = authenticate(samlMessageContext, authnResult.isAuthenticated(), authnResult
        //                    .getAuthenticatedAuthenticators(), SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD);

        try {
            builder = authenticate(authenticationContext, true, null, SAMLSSOConstants.AuthnModes
                    .USERNAME_PASSWORD);
        } catch (IdentityException e) {
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(authenticationContext);
            // TODO
            //            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
            //                    (122, SAMLSSOConstants.StatusCodes
            //                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.",
            // null));
            response.setGatewayResponseBuilder(builder);
            return response;
        }


        if (builder instanceof SAMLLoginResponse.SAMLLoginResponseBuilder) { // authenticated
            ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setRelayState(relayState);
            ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAcsUrl(samlMessageContext
                                                                                     .getAssertionConsumerURL());
            ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder)
                    .setSubject(SAMLSSOUtil.getSubject(authenticationContext));
            //                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAuthenticatedIdPs
            // (samlMessageContext
            //                        .getAuthenticationResult().getAuthenticatedIdPs());
            response.setGatewayResponseBuilder(builder);
            return response;
        } else { // authentication FAILURE
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setStatus(SAMLSSOConstants
                                                                                     .Notification.EXCEPTION_STATUS);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setMessageLog(SAMLSSOConstants
                                                                                         .Notification
                                                                                         .EXCEPTION_MESSAGE);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(samlMessageContext
                                                                                     .getResponseHandlerConfig()
                                                                                     .getDefaultAssertionConsumerUrl());
            response.setGatewayResponseBuilder(builder);
            return response;
        }
    }

    @Override
    public boolean canHandle(AuthenticationContext authenticationContext, GatewayException e) {
        return false;
    }

    @Override
    public boolean canHandle(AuthenticationContext authenticationContext, GatewayRuntimeException e) {
        return false;
    }

    public boolean canHandle(MessageContext messageContext) {
        if (messageContext instanceof AuthenticationContext) {
            return ((AuthenticationContext) messageContext)
                    .getInitialAuthenticationRequest() instanceof SAMLIDPInitRequest;
        }
        return false;
    }

    public String getName() {
        return "SAMLIdpInitResponseHandler";
    }

    public int getPriority(MessageContext messageContext) {
        return 16;
    }

    private SAMLResponse.SAMLResponseBuilder authenticate(AuthenticationContext authenticationContext,
                                                          boolean isAuthenticated,
                                                          String authenticators,
                                                          String authMode) throws
                                                                           IdentityException {

        SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext
                .getParameter(SAMLSSOConstants.SAMLContext);
        SAMLResponseHandlerConfig samlResponseHandlerConfig = messageContext.getResponseHandlerConfig();
        SAMLResponse.SAMLResponseBuilder builder;

        // TODO : persist the session
        if (isAuthenticated) {
            builder = new SAMLLoginResponse.SAMLLoginResponseBuilder(authenticationContext);
            String respString = setResponse(authenticationContext, ((SAMLLoginResponse.SAMLLoginResponseBuilder)
                    builder));
            if (log.isDebugEnabled()) {
                log.debug("Authentication successfully processed. The SAMLResponse is :" + respString);
            }
            return builder;
        } else {
            List<String> statusCodes = new ArrayList<String>();
            statusCodes.add(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE);
            statusCodes.add(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR);
            if (log.isDebugEnabled()) {
                log.debug("Error processing the authentication request.");
            }
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse
                    (null, statusCodes, "Authentication Failure, invalid username or password.", null));
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder)
                    .setAcsUrl(samlResponseHandlerConfig.getLoginPageURL());
            return builder;
        }
    }
}
