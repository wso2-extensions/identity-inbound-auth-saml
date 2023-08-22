/*
 * Copyright (c) (2010-2023), WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
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
package org.wso2.carbon.identity.sso.saml.processors;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.Response;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.builders.ErrorResponseBuilder;
import org.wso2.carbon.identity.sso.saml.builders.ResponseBuilder;
import org.wso2.carbon.identity.sso.saml.builders.SAMLArtifactBuilder;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSORespDTO;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponentHolder;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.utils.DiagnosticLog;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.LogConstants.ActionIDs.VALIDATE_SAML_REQUEST;
import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.LogConstants.InputKeys.SAML_REQUEST;
import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.LogConstants.SAML_INBOUND_SERVICE;

public class IdPInitSSOAuthnRequestProcessor implements SSOAuthnRequestProcessor {

    private static final Log log = LogFactory.getLog(IdPInitSSOAuthnRequestProcessor.class);

    public SAMLSSORespDTO process(SAMLSSOAuthnReqDTO authnReqDTO, String sessionId,
                                  boolean isAuthenticated, String authenticators, String authMode) throws Exception {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SAML_INBOUND_SERVICE, VALIDATE_SAML_REQUEST);
            diagnosticLogBuilder.resultMessage("Validating IDP initiated SAML Authentication Request.")
                    .inputParam(SAML_REQUEST, authnReqDTO.getRequestMessageString())
                    .inputParam("auth mode", authMode)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        try {
            SAMLSSOServiceProviderDO serviceProviderConfigs = getServiceProviderConfig(authnReqDTO);


            if (serviceProviderConfigs == null) {
                String msg =
                        "A SAML Service Provider with the Issuer '" + authnReqDTO.getIssuer() + "' is not registered." +
                        " Service Provider should be registered in advance.";
                log.warn(msg);
                return buildErrorResponse(authnReqDTO.getId(),
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null);
            }

            if (!serviceProviderConfigs.isIdPInitSSOEnabled()) {
                String msg = "IdP initiated SSO not enabled for service provider '" + authnReqDTO.getIssuer() + "'.";
                log.debug(msg);
                return buildErrorResponse(null,
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null);
            }

            if (serviceProviderConfigs.isEnableAttributesByDefault() && serviceProviderConfigs.getAttributeConsumingServiceIndex() != null) {
                authnReqDTO.setAttributeConsumingServiceIndex(Integer
                        .parseInt(serviceProviderConfigs
                                .getAttributeConsumingServiceIndex()));
            }

            // reading the service provider configs
            populateServiceProviderConfigs(serviceProviderConfigs, authnReqDTO);

            String acsUrl = authnReqDTO.getAssertionConsumerURL();
            if (StringUtils.isBlank(acsUrl) || !serviceProviderConfigs.getAssertionConsumerUrlList().contains
                    (acsUrl)) {
                String msg = "ALERT: Invalid Assertion Consumer URL value '" + acsUrl + "' in the " +
                             "AuthnRequest message from  the issuer '" + serviceProviderConfigs.getIssuer() +
                             "'. Possibly " + "an attempt for a spoofing attack";
                log.error(msg);
                return buildErrorResponse(authnReqDTO.getId(),
                                          SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, acsUrl);
            }

            // if subject is specified in AuthnRequest only that user should be
            // allowed to logged-in
            if (authnReqDTO.getSubject() != null && authnReqDTO.getUser() != null) {
                String authenticatedSubjectIdentifier =
                        authnReqDTO.getUser().getAuthenticatedSubjectIdentifier();
                if (authenticatedSubjectIdentifier != null &&
                        !authenticatedSubjectIdentifier.equals(authnReqDTO.getSubject())) {
                    String msg = "Provided username does not match with the requested subject";
                    log.warn(msg);

                    List<String> statusCodes = new ArrayList<>();
                    statusCodes.add(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE);
                    statusCodes.add(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR);

                    return buildErrorResponse(authnReqDTO.getId(),
                            statusCodes, msg, authnReqDTO.getAssertionConsumerURL());
                }
            }

            // persist the session
            SSOSessionPersistenceManager sessionPersistenceManager = SSOSessionPersistenceManager.getPersistenceManager();

            SAMLSSORespDTO samlssoRespDTO = null;
            String sessionIndexId = null;

            if (isAuthenticated) {
                if (sessionId != null && sessionPersistenceManager.isExistingTokenId(sessionId,
                        authnReqDTO.getLoggedInTenantDomain())) {
                    sessionIndexId = sessionPersistenceManager.getSessionIndexFromTokenId(sessionId,
                            authnReqDTO.getLoggedInTenantDomain());
                } else {
                    sessionIndexId = UUID.randomUUID().toString();
                    sessionPersistenceManager.persistSession(sessionId, sessionIndexId,
                            authnReqDTO.getLoggedInTenantDomain());
                }

                if (authMode.equals(SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD)) {
                    SAMLSSOServiceProviderDO spDO = new SAMLSSOServiceProviderDO();
                    spDO.setIssuer(authnReqDTO.getIssuer());
                    spDO.setAssertionConsumerUrl(authnReqDTO.getAssertionConsumerURL());
                    spDO.setCertAlias(authnReqDTO.getCertAlias());
                    spDO.setSloResponseURL(authnReqDTO.getSloResponseURL());
                    spDO.setSloRequestURL(authnReqDTO.getSloRequestURL());
                    spDO.setTenantDomain(authnReqDTO.getTenantDomain());
                    spDO.setDoSingleLogout(authnReqDTO.isDoSingleLogout());
                    spDO.setDoFrontChannelLogout(authnReqDTO.isDoFrontChannelLogout());
                    spDO.setFrontChannelLogoutBinding(authnReqDTO.getFrontChannelLogoutBinding());
                    spDO.setIdPInitSLOEnabled(authnReqDTO.isIdPInitSLOEnabled());
                    spDO.setAssertionConsumerUrls(authnReqDTO.getAssertionConsumerURLs());
                    spDO.setIdpInitSLOReturnToURLs(authnReqDTO.getIdpInitSLOReturnToURLs());
                    spDO.setSigningAlgorithmUri(authnReqDTO.getSigningAlgorithmUri());
                    spDO.setDigestAlgorithmUri(authnReqDTO.getDigestAlgorithmUri());
                    spDO.setAssertionEncryptionAlgorithmUri(authnReqDTO.getAssertionEncryptionAlgorithmUri());
                    spDO.setKeyEncryptionAlgorithmUri(authnReqDTO.getKeyEncryptionAlgorithmUri());
                    spDO.setEnableSAML2ArtifactBinding(authnReqDTO.isSAML2ArtifactBindingEnabled());
                    spDO.setDoValidateSignatureInRequests(authnReqDTO.isDoValidateSignatureInRequests());
                    spDO.setDoValidateSignatureInArtifactResolve(authnReqDTO.isDoValidateSignatureInArtifactResolve());
                    if (SAMLSSOUtil.isSAMLIdpInitLogoutResponseSigningEnabled()) {
                        spDO.setDoSignResponse(authnReqDTO.isDoSignResponse());
                    }
                    sessionPersistenceManager.persistSession(sessionIndexId,
                            authnReqDTO.getUser().getAuthenticatedSubjectIdentifier(), spDO,
                            authnReqDTO.getRpSessionId(), authnReqDTO.getIssuer(),
                            authnReqDTO.getAssertionConsumerURL(),
                            authnReqDTO.getLoggedInTenantDomain());
                }

                // Build the response for the successful scenario
                samlssoRespDTO = new SAMLSSORespDTO();

                if (authnReqDTO.isSAML2ArtifactBindingEnabled()) {
                    // Build and store SAML artifact
                    SAMLArtifactBuilder samlArtifactBuilder = new SAMLArtifactBuilder();
                    String artifact = samlArtifactBuilder.buildSAML2Artifact(authnReqDTO, sessionIndexId);

                    if (log.isDebugEnabled()) {
                        log.debug("Built SAML2 artifact for [SP: " + authnReqDTO.getIssuer() + ", subject: " +
                                authnReqDTO.getSubject()  + ", tenant: " + authnReqDTO.getTenantDomain() +
                                "] -> Artifact: " + artifact);
                    }

                    samlssoRespDTO.setRespString(artifact);
                } else {
                    // Build response with SAML assertion.
                    ResponseBuilder respBuilder = SAMLSSOUtil.getResponseBuilder();
                    if (respBuilder != null) {

                        Response response = respBuilder.buildResponse(authnReqDTO, sessionIndexId);
                        String samlResp = SAMLSSOUtil.marshall(response);

                        if (log.isDebugEnabled()) {
                            log.debug(samlResp);
                        }

                        samlssoRespDTO.setRespString(SAMLSSOUtil.encode(samlResp));
                    } else {
                        throw new Exception("Response builder not available.");
                    }
                }

                samlssoRespDTO.setSessionEstablished(true);
                samlssoRespDTO.setAssertionConsumerURL(authnReqDTO.getAssertionConsumerURL());
                samlssoRespDTO.setLoginPageURL(authnReqDTO.getLoginPageURL());
                samlssoRespDTO.setSubject(authnReqDTO.getUser());
            }

            if (samlssoRespDTO.getRespString() != null) {
                if (log.isDebugEnabled()) {
                    log.debug(samlssoRespDTO.getRespString());
                }
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        SAML_INBOUND_SERVICE, VALIDATE_SAML_REQUEST);
                diagnosticLogBuilder.resultMessage("SAML Request validation successful.")
                        .inputParam(SAMLSSOConstants.LogConstants.InputKeys.CONSUMER_URL,
                                samlssoRespDTO.getAssertionConsumerURL())
                        .inputParam(SAMLSSOConstants.LogConstants.InputKeys.ISSUER, authnReqDTO.getIssuer())
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
                Optional.ofNullable(samlssoRespDTO.getSubject()).ifPresent(subject -> {
                            String userName = LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(
                                    subject.getUserName()) : subject.getUserName();
                            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.USER_ID,
                                            SAMLSSOUtil.getUserId(subject))
                                    .inputParam(LogConstants.InputKeys.USER, userName);
                        });
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return samlssoRespDTO;
        } catch (Exception e) {
            log.error("Error processing the authentication request", e);

            List<String> statusCodes = new ArrayList<String>();
            statusCodes.add(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE);
            statusCodes.add(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR);

            SAMLSSORespDTO errorResp =
                    buildErrorResponse(authnReqDTO.getId(),
                            statusCodes,
                            "Error processing the authentication request.", null);
            errorResp.setLoginPageURL(authnReqDTO.getLoginPageURL());
            errorResp.setAssertionConsumerURL(authnReqDTO.getAssertionConsumerURL());
            return errorResp;
        }
    }


    /**
     * Returns the configured service provider configurations. The
     * configurations are taken from the user registry or from the
     * sso-idp-config.xml configuration file. In Stratos deployment the
     * configurations are read from the sso-idp-config.xml file.
     *
     * @param authnReqDTO
     * @return
     * @throws IdentityException
     */
    private SAMLSSOServiceProviderDO getServiceProviderConfig(SAMLSSOAuthnReqDTO authnReqDTO)
            throws IdentityException {
        try {
            SSOServiceProviderConfigManager stratosIdpConfigManager = SSOServiceProviderConfigManager
                    .getInstance();
            SAMLSSOServiceProviderDO ssoIdpConfigs = stratosIdpConfigManager
                    .getServiceProvider(authnReqDTO.getIssuer());
            if (ssoIdpConfigs == null) {
                int tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
                ssoIdpConfigs = IdentitySAMLSSOServiceComponentHolder.getInstance().getSAMLSSOServiceProviderManager()
                        .getServiceProvider(authnReqDTO.getIssuer(), tenantID);
                authnReqDTO.setStratosDeployment(false); // not stratos
            } else {
                authnReqDTO.setStratosDeployment(true); // stratos deployment
            }
            return ssoIdpConfigs;
        } catch (Exception e) {
            throw IdentityException.error("Error while reading Service Provider configurations", e);
        }
    }

    /**
     * Populate the configurations of the service provider
     *
     * @param ssoIdpConfigs
     * @param authnReqDTO
     * @throws IdentityException
     */
    private void populateServiceProviderConfigs(SAMLSSOServiceProviderDO ssoIdpConfigs,
                                                SAMLSSOAuthnReqDTO authnReqDTO)
            throws IdentityException {

        if (StringUtils.isBlank(authnReqDTO.getAssertionConsumerURL())) {
            authnReqDTO.setAssertionConsumerURL(ssoIdpConfigs.getDefaultAssertionConsumerUrl());
        }
        authnReqDTO.setLoginPageURL(ssoIdpConfigs.getLoginPageURL());
        authnReqDTO.setCertAlias(ssoIdpConfigs.getCertAlias());
        authnReqDTO.setNameIdClaimUri(ssoIdpConfigs.getNameIdClaimUri());
        authnReqDTO.setNameIDFormat(ssoIdpConfigs.getNameIDFormat());
        authnReqDTO.setDoSingleLogout(ssoIdpConfigs.isDoSingleLogout());
        authnReqDTO.setSloResponseURL(ssoIdpConfigs.getSloResponseURL());
        authnReqDTO.setSloRequestURL(ssoIdpConfigs.getSloRequestURL());
        authnReqDTO.setDoFrontChannelLogout(ssoIdpConfigs.isDoFrontChannelLogout());
        authnReqDTO.setFrontChannelLogoutBinding(ssoIdpConfigs.getFrontChannelLogoutBinding());
        authnReqDTO.setDoSignResponse(ssoIdpConfigs.isDoSignResponse());
        authnReqDTO.setDoSignAssertions(ssoIdpConfigs.isDoSignAssertions());
        authnReqDTO.setRequestedClaims(ssoIdpConfigs.getRequestedClaims());
        authnReqDTO.setRequestedAudiences(ssoIdpConfigs.getRequestedAudiences());
        authnReqDTO.setRequestedRecipients(ssoIdpConfigs.getRequestedRecipients());
        authnReqDTO.setDoEnableEncryptedAssertion(ssoIdpConfigs.isDoEnableEncryptedAssertion());
        authnReqDTO.setIdPInitSLOEnabled(ssoIdpConfigs.isIdPInitSLOEnabled());
        authnReqDTO.setAssertionConsumerURLs(ssoIdpConfigs.getAssertionConsumerUrls());
        authnReqDTO.setIdpInitSLOReturnToURLs(ssoIdpConfigs.getIdpInitSLOReturnToURLs());
        authnReqDTO.setSigningAlgorithmUri(ssoIdpConfigs.getSigningAlgorithmUri());
        authnReqDTO.setDigestAlgorithmUri(ssoIdpConfigs.getDigestAlgorithmUri());
        authnReqDTO.setAssertionEncryptionAlgorithmUri(ssoIdpConfigs.getAssertionEncryptionAlgorithmUri());
        authnReqDTO.setKeyEncryptionAlgorithmUri(ssoIdpConfigs.getKeyEncryptionAlgorithmUri());
        authnReqDTO.setAssertionQueryRequestProfileEnabled(ssoIdpConfigs.isAssertionQueryRequestProfileEnabled());
        authnReqDTO.setEnableSAML2ArtifactBinding(ssoIdpConfigs.isEnableSAML2ArtifactBinding());
        authnReqDTO.setDoValidateSignatureInArtifactResolve(ssoIdpConfigs.isDoValidateSignatureInArtifactResolve());
    }

    /**
     * @param id
     * @param status
     * @param statMsg
     * @return
     * @throws Exception
     */
    private SAMLSSORespDTO buildErrorResponse(String id, String status,
                                              String statMsg, String destination) throws Exception {

        List<String> statusCodeList = new ArrayList<String>();
        statusCodeList.add(status);
        return buildErrorResponse(id, statusCodeList, statMsg, destination);
    }

    private SAMLSSORespDTO buildErrorResponse(String id, List<String> statusCodeList,
                                              String statMsg, String destination) throws Exception {

        SAMLSSORespDTO samlSSORespDTO = new SAMLSSORespDTO();
        ErrorResponseBuilder errRespBuilder = new ErrorResponseBuilder();
        Response resp = errRespBuilder.buildResponse(id, statusCodeList, statMsg, destination);
        String encodedResponse = SAMLSSOUtil.compressResponse(SAMLSSOUtil.marshall(resp));

        samlSSORespDTO.setRespString(encodedResponse);
        samlSSORespDTO.setSessionEstablished(false);
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SAML_INBOUND_SERVICE, VALIDATE_SAML_REQUEST);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .inputParam(SAML_REQUEST, id)
                    .inputParam("error saml response", encodedResponse)
                    .resultMessage("An error occurred while processing the SAML request.")
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return samlSSORespDTO;
    }
}
