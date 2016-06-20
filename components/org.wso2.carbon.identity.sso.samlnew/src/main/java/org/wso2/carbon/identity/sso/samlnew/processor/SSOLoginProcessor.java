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

package org.wso2.carbon.identity.sso.samlnew.processor;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.samlnew.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.samlnew.bean.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.samlnew.bean.message.request.SAMLIdentityRequest;
import org.wso2.carbon.identity.sso.samlnew.bean.message.response.SAMLErrorResponse;
import org.wso2.carbon.identity.sso.samlnew.bean.message.response.SAMLLoginResponse;
import org.wso2.carbon.identity.sso.samlnew.bean.message.response.SAMLResponse;
import org.wso2.carbon.identity.sso.samlnew.exception.SAML2ClientException;
import org.wso2.carbon.identity.sso.samlnew.util.SAMLSSOUtil;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SSOLoginProcessor extends IdentityProcessor {
    private static Log log = LogFactory.getLog(SSOLoginProcessor.class);

    @Override
    public String getName() {
        return "SSOLoginProcessor";
    }

    public int getPriority() {
        return -1;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        IdentityMessageContext context = getContextIfAvailable(identityRequest);
        if (context != null) {
            if (context.getRequest() instanceof SAMLIdentityRequest) {
                return true;
            }
        }
        return false;
    }

    @Override
    public SAMLResponse.SAMLResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        SAMLMessageContext messageContext = (SAMLMessageContext) getContextIfAvailable(identityRequest);
        AuthenticationResult authnResult = processResponseFromFrameworkLogin(messageContext, identityRequest);
        SAMLResponse.SAMLResponseBuilder builder;
        AuthnRequest authnReq = messageContext.getAuthnRequest();


        if (authnResult == null || !authnResult.isAuthenticated()) {

            if (log.isDebugEnabled() && authnResult != null) {
                log.debug("Unauthenticated User.");
            }

            if (authnReq.isPassive()) { //if passive

                String destination = authnReq.getAssertionConsumerServiceURL();
                try {
                    List<String> statusCodes = new ArrayList<String>();
                    statusCodes.add(SAMLSSOConstants.StatusCodes.NO_PASSIVE);
                    statusCodes.add(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR);
                    String errorResponse = SAMLSSOUtil.buildErrorResponse(messageContext.getId(), statusCodes,
                            "Cannot authenticate Subject in Passive Mode", destination);
                    builder = new SAMLLoginResponse.SAMLLoginResponseBuilder(messageContext);
                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setRelayState(messageContext.getRelayState
                            ());
                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setRespString(errorResponse);
                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAcsUrl(messageContext
                            .getAssertionConsumerURL());
                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setSubject(messageContext.getSubject());
                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAuthenticatedIdPs(null);
                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setTenantDomain(messageContext
                            .getTenantDomain());
                    return builder;
                } catch (IdentityException e) {
                    //TODO
                    //Handle this exception
                }
            } else { // if forceAuthn or normal flow
                //TODO send a saml response with a status message.
                try {
                    if (!authnResult.isAuthenticated()) {
                        String destination = messageContext.getDestination();
                        String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE,
                                "User authentication failed", destination);
                        builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                        ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(errorResp);
                        ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setStatus(SAMLSSOConstants
                                .Notification.EXCEPTION_STATUS);
                        ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setMessageLog(SAMLSSOConstants
                                .Notification.EXCEPTION_MESSAGE);
                        ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(authnReq
                                .getAssertionConsumerServiceURL());
                        return builder;
                    } else {
                        throw IdentityException.error("Session data is not found for authenticated user");
                    }
                }catch(IdentityException | IOException e){
                    //TODO
                    //Handle This exception
                }
            }
        } else {
            SAMLSSOUtil.setIsSaaSApplication(authnResult.isSaaSApp());
            try {
                SAMLSSOUtil.setUserTenantDomain(authnResult.getSubject().getTenantDomain());
            } catch (UserStoreException e) {
                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                return builder;
            } catch (IdentityException e) {
                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                return builder;
            }
            try {
                SAMLSSOUtil.setUserTenantDomain(authnResult.getSubject().getTenantDomain());
            }catch(UserStoreException | IdentityException e){
                    //TODO
                    //Handle this exception
            }

            String relayState;
//TODO : Fix Identity Request in framework
            try {
                relayState = identityRequest.getParameter(SAMLSSOConstants.RELAY_STATE);
                if(StringUtils.isBlank(relayState)){
                    relayState = messageContext.getRelayState();
                }
            } catch (NullPointerException e) {
                relayState = messageContext.getRelayState();
            }

//            if (identityRequest.getParameter(SAMLSSOConstants.RELAY_STATE) != null) {
//                relayState = identityRequest.getParameter(SAMLSSOConstants.RELAY_STATE);
//            } else {
//                relayState = messageContext.getRelayState();
//            }

//            startTenantFlow(authnReqDTO.getTenantDomain());

//            if (sessionId == null) {
//                sessionId = UUIDGenerator.generateUUID();
//            }
            try {
                builder = authenticate(messageContext, authnResult.isAuthenticated(), authnResult
                        .getAuthenticatedAuthenticators(), SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD);
                if (builder instanceof SAMLLoginResponse.SAMLLoginResponseBuilder) { // authenticated
//
//                storeTokenIdCookie(sessionId, req, resp, authnReqDTO.getTenantDomain());
//                removeSessionDataFromCache(req.getParameter(SAMLSSOConstants.SESSION_DATA_KEY));
                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setRelayState(relayState);
                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAcsUrl(messageContext
                            .getAssertionConsumerURL());
                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setSubject(messageContext.getUser()
                            .getAuthenticatedSubjectIdentifier());
                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAuthenticatedIdPs(messageContext
                            .getAuthenticationResult().getAuthenticatedIdPs());
                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setTenantDomain(messageContext
                            .getTenantDomain
                            ());
                    return builder;
                } else { // authentication FAILURE
                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setStatus(SAMLSSOConstants
                            .Notification.EXCEPTION_STATUS);
                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setMessageLog(SAMLSSOConstants
                            .Notification.EXCEPTION_MESSAGE);
                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(messageContext
                            .getSamlssoServiceProviderDO().getDefaultAssertionConsumerUrl());
                    return builder;
                }
            } catch (IdentityException e) {

            }
        }
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    /**
     * @param id
     * @param status
     * @param statMsg
     * @return
     * @throws Exception
     */
    private String buildErrorResponse(String id, String status, String statMsg, String destination) throws
            IdentityException {

        List<String> statusCodeList = new ArrayList<String>();
        statusCodeList.add(status);
        return SAMLSSOUtil.buildErrorResponse(id, statusCodeList, statMsg, destination);
    }

    private SAMLResponse.SAMLResponseBuilder authenticate(SAMLMessageContext messageContext, boolean isAuthenticated, String authenticators,
                                 String authMode) throws IdentityException{
        SAMLSSOServiceProviderDO serviceProviderConfigs = messageContext.getSamlssoServiceProviderDO();
        SAMLResponse.SAMLResponseBuilder builder;
        // reading the service provider configs
        //populateServiceProviderConfigs(serviceProviderConfigs, authnReqDTO);
        try {
            if (serviceProviderConfigs.isDoValidateSignatureInRequests()) {
                List<String> idpUrlSet = SAMLSSOUtil.getDestinationFromTenantDomain(messageContext.getTenantDomain());

                if (messageContext.getDestination() == null || !idpUrlSet.contains(messageContext.getDestination())) {
                    String msg = "Destination validation for Authentication Request failed. " + "Received: [" +
                            messageContext.getDestination() + "]." + " Expected one in the list: [" + StringUtils
                            .join(idpUrlSet, ',') + "]";
                    if (log.isDebugEnabled()) {
                        log.debug(msg);
                    }
                    builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                            (messageContext.getId(), SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null));
                    return builder;
                }

                // validate the signature
                boolean isSignatureValid = SAMLSSOUtil.validateAuthnRequestSignature(messageContext);

                if (!isSignatureValid) {
                    String msg = "Signature validation for Authentication Request failed.";
                    if (log.isDebugEnabled()) {
                        log.debug(msg);
                    }
                    builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                            (messageContext.getId(), SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null));
                    return builder;
                }
            } else {
                //Validate the assertion consumer url,  only if request is not signed.
                String acsUrl = messageContext.getAssertionConsumerURL();
                if (StringUtils.isBlank(acsUrl) || !serviceProviderConfigs.getAssertionConsumerUrlList().contains
                        (acsUrl)) {
                    String msg = "ALERT: Invalid Assertion Consumer URL value '" + acsUrl + "' in the " +
                            "AuthnRequest message from  the issuer '" + serviceProviderConfigs.getIssuer() +
                            "'. Possibly " + "an attempt for a spoofing attack";
                    if (log.isDebugEnabled()) {
                        log.debug(msg);
                    }
                    builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                            (messageContext.getId(), SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, acsUrl));
                    return builder;
                }
            }

            // if subject is specified in AuthnRequest only that user should be allowed to logged-in
            if (messageContext.getSubject() != null && messageContext.getUser() != null) {
                String authenticatedSubjectIdentifier = messageContext.getUser().getAuthenticatedSubjectIdentifier();
                if (authenticatedSubjectIdentifier != null && !authenticatedSubjectIdentifier.equals(messageContext
                        .getSubject())) {
                    String msg = "Provided username does not match with the requested subject";
                    if (log.isDebugEnabled()) {
                        log.debug(msg);
                    }
                    builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                            (messageContext.getId(), SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg,
                                    serviceProviderConfigs.getDefaultAssertionConsumerUrl()));
                    return builder;
                }
            }

            // persist the session
//            SSOSessionPersistenceManager sessionPersistenceManager = SSOSessionPersistenceManager
//                    .getPersistenceManager();
//
//            SAMLSSORespDTO samlssoRespDTO = null;
//            String sessionIndexId = null;

            if (isAuthenticated) {
//                if (sessionId != null && sessionPersistenceManager.isExistingTokenId(sessionId)) {
//                    sessionIndexId = sessionPersistenceManager.getSessionIndexFromTokenId(sessionId);
//                } else {
//                    sessionIndexId = UUIDGenerator.generateUUID();
//                    sessionPersistenceManager.persistSession(sessionId, sessionIndexId);
//                }

                //TODO check whether the same SP exists

//                if (authMode.equals(SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD)) {
//                    SAMLSSOServiceProviderDO spDO = new SAMLSSOServiceProviderDO();
//                    spDO.setIssuer(authnReqDTO.getIssuer());
//                    spDO.setAssertionConsumerUrl(authnReqDTO.getAssertionConsumerURL());
//                    spDO.setCertAlias(authnReqDTO.getCertAlias());
//                    spDO.setSloResponseURL(authnReqDTO.getSloResponseURL());
//                    spDO.setSloRequestURL(authnReqDTO.getSloRequestURL());
//                    spDO.setTenantDomain(authnReqDTO.getTenantDomain());
//                    spDO.setNameIDFormat(authnReqDTO.getNameIDFormat());
//                    spDO.setDoSingleLogout(authnReqDTO.isDoSingleLogout());
//                    spDO.setIdPInitSLOEnabled(authnReqDTO.isIdPInitSLOEnabled());
//                    spDO.setAssertionConsumerUrls(authnReqDTO.getAssertionConsumerURLs());
//                    spDO.setIdpInitSLOReturnToURLs(authnReqDTO.getIdpInitSLOReturnToURLs());
//                    spDO.setDoSignResponse(authnReqDTO.isDoSignResponse());
//                    spDO.setSigningAlgorithmUri(authnReqDTO.getSigningAlgorithmUri());
//                    spDO.setDigestAlgorithmUri(authnReqDTO.getDigestAlgorithmUri());
//                    sessionPersistenceManager.persistSession(sessionIndexId,
//                            authnReqDTO.getUser().getAuthenticatedSubjectIdentifier(),
//                            spDO, authnReqDTO.getRpSessionId(),
//                            authnReqDTO.getIssuer(),
//                            authnReqDTO.getAssertionConsumerURL());
//                }

                builder = new SAMLLoginResponse.SAMLLoginResponseBuilder(messageContext);
                String respString = ((SAMLLoginResponse.SAMLLoginResponseBuilder)builder).buildResponse();

                if (log.isDebugEnabled()) {
                    log.debug("Authentication successfully processed. The SAMLResponse is :" + respString);
                }
                return builder;
            }

        } catch (Exception e) {
            log.error("Error processing the authentication request", e);
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                     (messageContext.getId(), SAMLSSOConstants.StatusCodes
                     .AUTHN_FAILURE, "Authentication Failure, invalid username or password.", null));
            return builder;
        }

       return null;
    }

}
