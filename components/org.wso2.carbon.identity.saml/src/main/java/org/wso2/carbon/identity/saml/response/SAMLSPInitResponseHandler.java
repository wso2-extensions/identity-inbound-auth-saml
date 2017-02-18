package org.wso2.carbon.identity.saml.response;

import org.slf4j.Logger;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.gateway.api.response.FrameworkHandlerResponse;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.processor.handler.response.ResponseException;
import org.wso2.carbon.identity.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.request.SAMLSpInitRequest;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;

import java.util.ArrayList;
import java.util.List;

public class SAMLSPInitResponseHandler extends SAMLResponseHandler {

    private static Logger log = org.slf4j.LoggerFactory.getLogger(SAMLSPInitResponseHandler.class);

    @Override
    public FrameworkHandlerResponse buildErrorResponse(AuthenticationContext authenticationContext, IdentityException e) throws
                                                                                                     ResponseException {

        super.buildErrorResponse(authenticationContext, e);
        SAMLMessageContext samlMessageContext = (SAMLMessageContext) authenticationContext.getParameter(SAMLSSOConstants.SAMLContext);
        SAMLResponse.SAMLResponseBuilder builder;
        FrameworkHandlerResponse response = FrameworkHandlerResponse.REDIRECT;

        if (samlMessageContext.isPassive()) { //if passive
            String destination = samlMessageContext.getAssertionConsumerURL();
            List<String> statusCodes = new ArrayList<String>();
            statusCodes.add(SAMLSSOConstants.StatusCodes.NO_PASSIVE);
            statusCodes.add(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR);
            String errorResponse = null;
            try {
                errorResponse = SAMLSSOUtil.buildErrorResponse(samlMessageContext.getId(), statusCodes,
                        "Cannot process response from framework Subject in Passive Mode", destination);

                builder = new SAMLLoginResponse.SAMLLoginResponseBuilder(samlMessageContext);
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setRelayState(samlMessageContext.getRelayState
                        ());
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setRespString(errorResponse);
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAcsUrl(samlMessageContext
                        .getAssertionConsumerURL());
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setSubject(samlMessageContext.getSubject());
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAuthenticatedIdPs(null);
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setTenantDomain(samlMessageContext
                        .getTenantDomain());
                response.setIdentityResponseBuilder(builder);
            } catch (IdentityException ex) {
                ex.printStackTrace();
            }
        }


        builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(authenticationContext);
        // TODO
//            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                    (122, SAMLSSOConstants.StatusCodes
//                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.", null));
        response.setIdentityResponseBuilder(builder);
        return response;

    }

    @Override
    public FrameworkHandlerResponse buildResponse(AuthenticationContext authenticationContext) throws ResponseException {
        super.buildResponse(authenticationContext);
        // TODO

//        if (identityMessageContext.getSubject() != null && messageContext.getUser() != null) {
//            String authenticatedSubjectIdentifier = messageContext.getUser().getAuthenticatedSubjectIdentifier();
//            if (authenticatedSubjectIdentifier != null && !authenticatedSubjectIdentifier.equals(messageContext
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

        SAMLResponse.SAMLResponseBuilder builder;
        FrameworkHandlerResponse response = FrameworkHandlerResponse.REDIRECT;

        builder = new SAMLLoginResponse.SAMLLoginResponseBuilder(authenticationContext);
        String respString = null;
        try {
            respString = setResponse(authenticationContext, ((SAMLLoginResponse.SAMLLoginResponseBuilder)
                    builder));
            //((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAcsUrl()
        } catch (IdentityException e) {

            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(authenticationContext);
            // TODO
//            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                    (122, SAMLSSOConstants.StatusCodes
//                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.", null));
            response.setIdentityResponseBuilder(builder);
            return response;
        }

        if (log.isDebugEnabled()) {
            log.debug("Authentication successfully processed. The SAMLResponse is :" + respString);
        }
        response.setIdentityResponseBuilder(builder);
        return response;
    }


    public boolean canHandle(MessageContext messageContext) {
        if (messageContext instanceof AuthenticationContext) {
            return ((AuthenticationContext) messageContext).getInitialAuthenticationRequest() instanceof SAMLSpInitRequest;
        }
        return false;
    }

    public String getName() {
        return "SPInitResponseHandler";
    }

    public int getPriority(MessageContext messageContext) {
        return 15;
    }

}
