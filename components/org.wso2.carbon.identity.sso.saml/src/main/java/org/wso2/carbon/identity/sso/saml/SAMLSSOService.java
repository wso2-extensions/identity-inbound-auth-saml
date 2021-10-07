/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sso.saml;

import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.core.xml.XMLObject;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.dto.QueryParamDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSORespDTO;
import org.wso2.carbon.identity.sso.saml.dto.SingleLogoutRequestDTO;
import org.wso2.carbon.identity.sso.saml.logout.LogoutRequestSender;
import org.wso2.carbon.identity.sso.saml.extension.SAMLExtensionProcessor;
import org.wso2.carbon.identity.sso.saml.processors.IdPInitLogoutRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.IdPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.SPInitLogoutRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.SPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.session.SessionInfoData;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.sso.saml.validators.SSOAuthnRequestValidator;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class SAMLSSOService {

    public static boolean isOpenIDLoginAccepted() {
        if (IdentityUtil.getProperty(IdentityConstants.ServerConfig.ACCEPT_OPENID_LOGIN) != null &&
                !"".equals(IdentityUtil.getProperty(IdentityConstants.ServerConfig.ACCEPT_OPENID_LOGIN).trim())) {
            return Boolean.parseBoolean(IdentityUtil.getProperty(IdentityConstants.ServerConfig.ACCEPT_OPENID_LOGIN).trim());
        } else {
            return false;
        }
    }

    public static boolean isSAMLSSOLoginAccepted() {
        if (IdentityUtil.getProperty(IdentityConstants.ServerConfig.ACCEPT_SAMLSSO_LOGIN) != null &&
                !"".equals(IdentityUtil.getProperty(IdentityConstants.ServerConfig.ACCEPT_SAMLSSO_LOGIN).trim())) {
            return Boolean.parseBoolean(IdentityUtil.getProperty(IdentityConstants.ServerConfig.ACCEPT_SAMLSSO_LOGIN).trim());
        } else {
            return false;
        }
    }

    /**
     * Validates the SAMLRquest, the request can be the type AuthnRequest or
     * LogoutRequest. The SigAlg and Signature parameter will be used only with
     * the HTTP Redirect binding. With HTTP POST binding these values are null.
     * If the user already having a SSO session then the Response
     * will be returned if not only the validation results will be returned.
     *
     * @param samlReq
     * @param queryString
     * @param sessionId
     * @param rpSessionId
     * @param authnMode
     * @return
     * @throws IdentityException
     *
     * @deprecated This method was deprecated to move SAMLSSOParticipantCache to the tenant space.
     * Use {@link #validateSPInitSSORequest(String, String, String, String, String, boolean, String)} instead.
     */
    public SAMLSSOReqValidationResponseDTO validateSPInitSSORequest(String samlReq, String queryString,
                                                                    String sessionId, String rpSessionId,
                                                                    String authnMode, boolean isPost)
            throws IdentityException {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return validateSPInitSSORequest(samlReq, queryString, sessionId, rpSessionId, authnMode, isPost,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Validates the SAMLRquest, the request can be the type AuthnRequest or
     * LogoutRequest. The SigAlg and Signature parameter will be used only with
     * the HTTP Redirect binding. With HTTP POST binding these values are null.
     * If the user already having a SSO session then the Response
     * will be returned if not only the validation results will be returned.
     * Logged in Tenant Domain will be used to maintain the caches in tenant space.
     *
     * @param samlReq              SAML Request
     * @param queryString          Query String
     * @param sessionId            Session ID
     * @param rpSessionId          rpSession Id
     * @param authnMode            Authn Mode
     * @param isPost               Is Post
     * @param loggedInTenantDomain Logged in tenant domain
     * @return validationResp
     * @throws IdentityException
     */
    public SAMLSSOReqValidationResponseDTO validateSPInitSSORequest(String samlReq, String queryString,
                                                                    String sessionId, String rpSessionId,
                                                                    String authnMode, boolean isPost,
                                                                    String loggedInTenantDomain)
            throws IdentityException {

        SAMLSSOReqValidationResponseDTO validationResp = null;
        XMLObject request;

        if (isPost) {
            request = SAMLSSOUtil.unmarshall(SAMLSSOUtil.decodeForPost(samlReq));
        } else {
            request = SAMLSSOUtil.unmarshall(SAMLSSOUtil.decode(samlReq));
        }

        if (request instanceof AuthnRequest) {
            SSOAuthnRequestValidator authnRequestValidator =
                    SAMLSSOUtil.getSPInitSSOAuthnRequestValidator((AuthnRequest) request, queryString);
            validationResp = authnRequestValidator.validate();
            validationResp.setRequestMessageString(samlReq);
            validationResp.setQueryString(queryString);
            validationResp.setRpSessionId(rpSessionId);
            validationResp.setIdPInitSSO(false);
        } else if (request instanceof LogoutRequest) {
            SPInitLogoutRequestProcessor logoutReqProcessor = SAMLSSOUtil.getSPInitLogoutRequestProcessor();
            validationResp =
                    logoutReqProcessor.process((LogoutRequest) request, sessionId, queryString, loggedInTenantDomain);
        }

        Extensions extensions = ((RequestAbstractType) request).getExtensions();
        if (extensions != null) {
            for (SAMLExtensionProcessor extensionProcessor : SAMLSSOUtil.getExtensionProcessors()) {
                if (extensionProcessor.canHandle((RequestAbstractType) request)) {
                    extensionProcessor.processSAMLExtensions((RequestAbstractType) request, validationResp);
                }
            }
        }
        return validationResp;
    }

    /**
     * validates the IdP Initiated SSO/SLO request.
     * If the user already having a SSO session then the Response
     * will be returned if not only the validation results will be returned.
     *
     * @param relayState
     * @param queryString
     * @param queryParamDTOs
     * @param serverURL
     * @param sessionId
     * @param rpSessionId
     * @param authnMode
     * @param isLogout
     * @return
     * @throws IdentityException
     *
     * @deprecated This method was deprecated to move saml caches to the tenant space.
     * Use {@link #validateIdPInitSSORequest(String,String,QueryParamDTO[],String,String,String,String,boolean,String)}
     * instead.
     */
    public SAMLSSOReqValidationResponseDTO validateIdPInitSSORequest(String relayState, String queryString,
                                                                     QueryParamDTO[] queryParamDTOs,
                                                                     String serverURL, String sessionId,
                                                                     String rpSessionId, String authnMode,
                                                                     boolean isLogout) throws IdentityException {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return validateIdPInitSSORequest(relayState, queryString, queryParamDTOs, serverURL, sessionId, rpSessionId,
                authnMode, isLogout, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * validates the IdP Initiated SSO/SLO request.
     * If the user already having a SSO session then the Response
     * will be returned if not only the validation results will be returned.
     *
     * @param relayState            Relay State
     * @param queryString           Query String
     * @param queryParamDTOs        Query Param DTOs
     * @param serverURL             Server url
     * @param sessionId             Session id
     * @param rpSessionId           Rp Session id
     * @param authnMode             Authn Mode
     * @param isLogout              Is Logout
     * @param loginTenantDomain     Login tenant Domain
     * @return      validationResponseDTO
     * @throws IdentityException
     */
    public SAMLSSOReqValidationResponseDTO validateIdPInitSSORequest(String relayState, String queryString,
                                                                     QueryParamDTO[] queryParamDTOs,
                                                                     String serverURL, String sessionId,
                                                                     String rpSessionId, String authnMode,
                                                                     boolean isLogout, String loginTenantDomain)
            throws IdentityException {

        SAMLSSOReqValidationResponseDTO validationResponseDTO = null;
        if (isLogout) {
            IdPInitLogoutRequestProcessor idPInitLogoutRequestProcessor =
                    SAMLSSOUtil.getIdPInitLogoutRequestProcessor();
            validationResponseDTO = idPInitLogoutRequestProcessor.process(sessionId, queryParamDTOs, serverURL,
                    loginTenantDomain);
            validationResponseDTO.setIdPInitSLO(true);
        } else {
            SSOAuthnRequestValidator authnRequestValidator = SAMLSSOUtil.getIdPInitSSOAuthnRequestValidator(
                    queryParamDTOs, relayState);
            validationResponseDTO = authnRequestValidator.validate();
            validationResponseDTO.setIdPInitSSO(true);
        }
        validationResponseDTO.setQueryString(queryString);
        validationResponseDTO.setRpSessionId(rpSessionId);
        return validationResponseDTO;
    }

    /**
     * @param authReqDTO
     * @param sessionId
     * @return
     * @throws IdentityException
     */
    public SAMLSSORespDTO authenticate(SAMLSSOAuthnReqDTO authReqDTO, String sessionId, boolean authenticated, String authenticators, String authMode)
            throws IdentityException {
        if (authReqDTO.isIdPInitSSOEnabled()) {
            IdPInitSSOAuthnRequestProcessor authnRequestProcessor = SAMLSSOUtil.getIdPInitSSOAuthnRequestProcessor();
            try {
                return authnRequestProcessor.process(authReqDTO, sessionId, authenticated, authenticators, authMode);
            } catch (Exception e) {
                throw IdentityException.error("Error when authenticating the users", e);
            }
        } else {
            SPInitSSOAuthnRequestProcessor authnRequestProcessor = SAMLSSOUtil.getSPInitSSOAuthnRequestProcessor();
            try {
                return authnRequestProcessor.process(authReqDTO, sessionId, authenticated, authenticators, authMode);
            } catch (Exception e) {
                throw IdentityException.error("Error when authenticating the users", e);
            }
        }

    }

    /**
     * Invalidates the SSO session for the given session ID
     *
     * @param sessionId
     * @return
     * @throws IdentityException
     * @deprecated use {@link #invalidateSession(String)} instead.
     */
    public SAMLSSOReqValidationResponseDTO doSingleLogout(String sessionId)
            throws IdentityException {
       return invalidateSession(sessionId);
    }

    /**
     * Invalidates the SSO session for the given session ID.
     * @param sessionId sessionId.
     * @return SAMLSSOReqValidationResponseDTO.
     * @throws IdentityException
     */
    public SAMLSSOReqValidationResponseDTO invalidateSession(String sessionId) throws IdentityException {

        String loginTenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if (IdentityTenantUtil.isTenantedSessionsEnabled()) {
            loginTenantDomain = IdentityTenantUtil.getTenantDomainFromContext();
        }
        SPInitLogoutRequestProcessor logoutReqProcessor = SAMLSSOUtil.getSPInitLogoutRequestProcessor();
        return logoutReqProcessor.process(null, sessionId, null, loginTenantDomain);
    }

    /**
     * Gets all the session participants from session ID send logout requests to them.
     *
     * @param sessionId
     * @param issuer
     * @throws IdentityException
     *
     * @deprecated This method was deprecated to move caches to the tenant space.
     * Use {@link #doSingleLogout(String, String, String)} )} instead.
     */
    public void doSingleLogout(String sessionId, String issuer) throws IdentityException {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        doSingleLogout(sessionId, issuer, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Gets all the session participants from session ID send logout requests to them.
     *
     * @param sessionId             Session Id.
     * @param issuer                Name of the issuer.
     * @param loginTenantDomain     Login Tenant Domain.
     * @throws IdentityException
     */
    public void doSingleLogout(String sessionId, String issuer, String loginTenantDomain) throws IdentityException {

        SAMLSSOReqValidationResponseDTO reqValidationResponseDTO = new SAMLSSOReqValidationResponseDTO();
        reqValidationResponseDTO.setLogOutReq(true);

        SSOSessionPersistenceManager ssoSessionPersistenceManager = SSOSessionPersistenceManager
                .getPersistenceManager();
        String sessionIndex = ssoSessionPersistenceManager.getSessionIndexFromTokenId(sessionId, loginTenantDomain);
        SessionInfoData sessionInfoData = ssoSessionPersistenceManager.getSessionInfo(sessionIndex, loginTenantDomain);
        if (sessionInfoData != null) {
            Map<String, SAMLSSOServiceProviderDO> sessionsList = sessionInfoData.getServiceProviderList();
            Map<String, String> rpSessionsList = sessionInfoData.getRPSessionsList();

            List<SingleLogoutRequestDTO> singleLogoutReqDTOs = new ArrayList<>();

            for (Map.Entry<String, SAMLSSOServiceProviderDO> entry : sessionsList.entrySet()) {
                String key = entry.getKey();
                SAMLSSOServiceProviderDO serviceProviderDO = entry.getValue();

                // If issuer is the logout request initiator, then not sending the logout request to the issuer.
                if (!key.equals(issuer) && serviceProviderDO.isDoSingleLogout()
                        && !serviceProviderDO.isDoFrontChannelLogout()) {
                    SingleLogoutRequestDTO logoutReqDTO = SAMLSSOUtil.createLogoutRequestDTO(serviceProviderDO,
                            sessionInfoData.getSubject(key), sessionIndex, rpSessionsList.get(key),
                            serviceProviderDO.getCertAlias(), serviceProviderDO.getTenantDomain());
                    singleLogoutReqDTOs.add(logoutReqDTO);
                }
            }

            // Send logout requests to all session participants.
            LogoutRequestSender.getInstance().sendLogoutRequests(singleLogoutReqDTOs.toArray(
                    new SingleLogoutRequestDTO[singleLogoutReqDTOs.size()]));
            SAMLSSOUtil.removeSession(sessionId, issuer, loginTenantDomain);
        }
    }

}
