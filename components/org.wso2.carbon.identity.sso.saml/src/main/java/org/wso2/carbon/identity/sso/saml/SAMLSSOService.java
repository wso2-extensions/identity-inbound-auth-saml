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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.builders.SingleLogoutMessageBuilder;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCache;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCacheKey;
import org.wso2.carbon.identity.sso.saml.dto.QueryParamDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSORespDTO;
import org.wso2.carbon.identity.sso.saml.dto.SingleLogoutRequestDTO;
import org.wso2.carbon.identity.sso.saml.logout.LogoutRequestSender;
import org.wso2.carbon.identity.sso.saml.processors.IdPInitLogoutRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.IdPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.SPInitLogoutRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.SPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.session.SessionInfoData;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.sso.saml.validators.IdPInitSSOAuthnRequestValidator;
import org.wso2.carbon.identity.sso.saml.validators.SPInitSSOAuthnRequestValidator;
import org.wso2.carbon.identity.sso.saml.validators.SSOAuthnRequestValidator;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class SAMLSSOService {

    private static Log log = LogFactory.getLog(SAMLSSOService.class);

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
     */
    public SAMLSSOReqValidationResponseDTO validateSPInitSSORequest(String samlReq, String queryString,
                                                                    String sessionId, String rpSessionId,
                                                                    String authnMode, boolean isPost)
            throws IdentityException {
        XMLObject request;

        if (isPost) {
            request = SAMLSSOUtil.unmarshall(SAMLSSOUtil.decodeForPost(samlReq));
        } else {
            request = SAMLSSOUtil.unmarshall(SAMLSSOUtil.decode(samlReq));
        }

        if (request instanceof AuthnRequest) {
            SSOAuthnRequestValidator authnRequestValidator =
                    SAMLSSOUtil.getSPInitSSOAuthnRequestValidator((AuthnRequest) request);
            SAMLSSOReqValidationResponseDTO validationResp = authnRequestValidator.validate();
            validationResp.setRequestMessageString(samlReq);
            validationResp.setQueryString(queryString);
            validationResp.setRpSessionId(rpSessionId);
            validationResp.setIdPInitSSO(false);

            return validationResp;
        } else if (request instanceof LogoutRequest) {
            SPInitLogoutRequestProcessor logoutReqProcessor = SAMLSSOUtil.getSPInitLogoutRequestProcessor();
            SAMLSSOReqValidationResponseDTO validationResponseDTO =
                    logoutReqProcessor.process((LogoutRequest) request,
                            sessionId,
                            queryString);
            return validationResponseDTO;
        }

        return null;
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
     */
    public SAMLSSOReqValidationResponseDTO validateIdPInitSSORequest(String relayState, String queryString,
                                                                     QueryParamDTO[] queryParamDTOs,
                                                                     String serverURL, String sessionId,
                                                                     String rpSessionId, String authnMode,
                                                                     boolean isLogout) throws IdentityException {

        SAMLSSOReqValidationResponseDTO validationResponseDTO = null;
        if(!isLogout) {
            SSOAuthnRequestValidator authnRequestValidator = SAMLSSOUtil.getIdPInitSSOAuthnRequestValidator(
                    queryParamDTOs, relayState);
            validationResponseDTO = authnRequestValidator.validate();
            validationResponseDTO.setIdPInitSSO(true);
        } else {
            IdPInitLogoutRequestProcessor idPInitLogoutRequestProcessor = SAMLSSOUtil.getIdPInitLogoutRequestProcessor();
            validationResponseDTO = idPInitLogoutRequestProcessor.process(sessionId, queryParamDTOs, serverURL);
            validationResponseDTO.setIdPInitSLO(true);
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
     */
    public SAMLSSOReqValidationResponseDTO doSingleLogout(String sessionId)
            throws IdentityException {
        SPInitLogoutRequestProcessor logoutReqProcessor = SAMLSSOUtil.getSPInitLogoutRequestProcessor();
        SAMLSSOReqValidationResponseDTO validationResponseDTO =
                logoutReqProcessor.process(null,
                        sessionId,
                        null);
        return validationResponseDTO;
    }

    public void doSingleLogout(String sessionId, String issuer)
            throws IdentityException {

        SAMLSSOReqValidationResponseDTO reqValidationResponseDTO = new SAMLSSOReqValidationResponseDTO();
        reqValidationResponseDTO.setLogOutReq(true);

        SSOSessionPersistenceManager ssoSessionPersistenceManager = SSOSessionPersistenceManager
                .getPersistenceManager();
        String sessionIndex = ssoSessionPersistenceManager.getSessionIndexFromTokenId(sessionId);
        SessionInfoData sessionInfoData = ssoSessionPersistenceManager.getSessionInfo(sessionIndex);

        Map<String, SAMLSSOServiceProviderDO> sessionsList = sessionInfoData
                .getServiceProviderList();
        SingleLogoutMessageBuilder logoutMsgBuilder = new SingleLogoutMessageBuilder();
        Map<String, String> rpSessionsList = sessionInfoData.getRPSessionsList();
        List<SingleLogoutRequestDTO> singleLogoutReqDTOs = new ArrayList<SingleLogoutRequestDTO>();

        for (Map.Entry<String, SAMLSSOServiceProviderDO> entry : sessionsList.entrySet()) {
            String key = entry.getKey();
            SAMLSSOServiceProviderDO value = entry.getValue();

            if (!key.equals(issuer)) {
                SingleLogoutRequestDTO logoutReqDTO = new SingleLogoutRequestDTO();
                if (StringUtils.isNotBlank(value.getSloRequestURL())) {
                    logoutReqDTO.setAssertionConsumerURL(value.getSloRequestURL());
                } else if (StringUtils.isNotBlank(value.getSloResponseURL())) {
                    logoutReqDTO.setAssertionConsumerURL(value.getSloResponseURL());
                } else {
                    logoutReqDTO.setAssertionConsumerURL(value.getAssertionConsumerUrl());
                }

                LogoutRequest logoutReq = logoutMsgBuilder.buildLogoutRequest(sessionInfoData.getSubject(key)
                        , sessionIndex, SAMLSSOConstants.SingleLogoutCodes.LOGOUT_USER, logoutReqDTO
                                .getAssertionConsumerURL(), value.getNameIDFormat(), value.getTenantDomain(), value
                                .getSigningAlgorithmUri(), value.getDigestAlgorithmUri());

                String logoutReqString = SAMLSSOUtil.marshall(logoutReq);
                logoutReqDTO.setLogoutResponse(logoutReqString);
                logoutReqDTO.setRpSessionId(rpSessionsList.get(key));
                singleLogoutReqDTOs.add(logoutReqDTO);
            }
        }

        LogoutRequestSender.getInstance().sendLogoutRequests(singleLogoutReqDTOs.toArray(
                new SingleLogoutRequestDTO[singleLogoutReqDTOs.size()]));

        if (!sessionIndex.isEmpty()) {
            SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey(sessionIndex);
            SAMLSSOParticipantCacheEntry cacheEntry = SAMLSSOParticipantCache.getInstance().getValueFromCache(cacheKey);
            if (cacheEntry.getSessionInfoData() != null && cacheEntry.getSessionInfoData().getServiceProviderList() != null) {

                Set<String> sloSupportedIssuers = new HashSet<>();
                //Filter out service providers which enabled the single logout
                for (Map.Entry<String, SAMLSSOServiceProviderDO> entry : cacheEntry.getSessionInfoData().
                        getServiceProviderList().entrySet()) {
                    if (entry.getValue().isDoSingleLogout()) {
                        sloSupportedIssuers.add(entry.getKey());
                    }
                }

                //Remove service providers which enabled the single logout
                for (String sloSupportedIssuer : sloSupportedIssuers) {
                    cacheEntry.getSessionInfoData().removeServiceProvider(sloSupportedIssuer);
                    if (log.isDebugEnabled()) {
                        log.debug("Removed SLO supported service provider from session info data  with name " + sloSupportedIssuer);
                    }
                }

            }

        }
    }

}
