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
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.builders.SingleLogoutMessageBuilder;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponentHolder;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.session.SessionInfoData;
import org.wso2.carbon.identity.sso.saml.util.LambdaExceptionUtils;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.sso.saml.validators.ValidationResult;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.LogConstants.ActionIDs.PROCESS_SAML_LOGOUT;
import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.LogConstants.SAML_INBOUND_SERVICE;

/**
 * Handles validation of SP initiated logout requests.
 */
public class SPInitLogoutRequestProcessor implements SPInitSSOLogoutRequestProcessor {

    private static final Log log = LogFactory.getLog(SPInitLogoutRequestProcessor.class);

    private String defaultSigningAlgoUri = IdentityApplicationManagementUtil.getSigningAlgoURIByConfig();
    private String defaultDigestAlgoUri = IdentityApplicationManagementUtil.getDigestAlgoURIByConfig();

    /**
     * @param logoutRequest
     * @param sessionId
     * @param queryString
     * @return
     * @throws IdentityException
     *
     * @deprecated This method was deprecated to move saml caches to the tenant space.
     * Use {@link #process(LogoutRequest, String, String, String)}  instead.
     */
    @Deprecated
    public SAMLSSOReqValidationResponseDTO process(LogoutRequest logoutRequest, String sessionId,
                                                   String queryString) throws IdentityException {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return process(logoutRequest, sessionId, queryString, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Process SP initiated Logout Request.
     *
     * @param logoutRequest     Logout Request
     * @param sessionId         Session Id
     * @param queryString       Query String
     * @param loginTenantDomain Login tenant domain
     * @return SAMLSSOReqValidationResponseDTO
     * @throws IdentityException
     */
    public SAMLSSOReqValidationResponseDTO process(LogoutRequest logoutRequest, String sessionId, String queryString,
                                                   String loginTenantDomain) throws IdentityException {

        SAMLSSOReqValidationResponseDTO reqValidationResponseDTO = new SAMLSSOReqValidationResponseDTO();
        reqValidationResponseDTO.setLogOutReq(true);
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SAML_INBOUND_SERVICE, PROCESS_SAML_LOGOUT);
            diagnosticLogBuilder.resultMessage("Processing SP initiated logout request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
            Optional.ofNullable(logoutRequest).map(LogoutRequest::getIssuer).map(Issuer::getValue)
                    .ifPresent(issuerValue -> diagnosticLogBuilder.inputParam(
                            SAMLSSOConstants.LogConstants.InputKeys.ISSUER, issuerValue));
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        try {

            // List of validators that we need to run before processing the logout.
            List<Function<LogoutRequest, ValidationResult<SAMLSSOReqValidationResponseDTO>>> logoutRequestValidators =
                    new ArrayList<>();

            // Validate logout request bean.
            logoutRequestValidators.add(LambdaExceptionUtils.rethrowFunction(this::validateLogoutRequest));

            // Validate the issuer of the logout request.
            logoutRequestValidators.add(LambdaExceptionUtils.rethrowFunction(this::validateIssuer));

            // Validate the subject of the logout request.
            logoutRequestValidators.add(LambdaExceptionUtils.rethrowFunction(this::validateSubject));

            // Run all validators against the logout request to validate.
            for (Function<LogoutRequest, ValidationResult<SAMLSSOReqValidationResponseDTO>> validator :
                    logoutRequestValidators) {
                ValidationResult<SAMLSSOReqValidationResponseDTO> validationResult = validator.apply(logoutRequest);
                if (!validationResult.getValidationStatus()) {
                    return validationResult.getValue();
                }
            }
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        SAML_INBOUND_SERVICE, PROCESS_SAML_LOGOUT);
                diagnosticLogBuilder.resultMessage("Logout request validation successful.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM);
                Optional.ofNullable(logoutRequest).flatMap(request -> Optional.ofNullable(request.getIssuer()))
                        .ifPresent(issuer -> diagnosticLogBuilder.inputParam(
                                SAMLSSOConstants.LogConstants.InputKeys.ISSUER, issuer.getValue()));
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }

            // Validate whether we have principle session.
            ValidationResult<SAMLSSOReqValidationResponseDTO> validationResult =
                    validatePrincipleSession(sessionId, logoutRequest, loginTenantDomain);
            if (!validationResult.getValidationStatus()) {
                return validationResult.getValue();
            }

            String issuer = logoutRequest.getIssuer().getValue();

            // Get the sessions from the SessionPersistenceManager and prepare the logout responses.
            SSOSessionPersistenceManager ssoSessionPersistenceManager = SSOSessionPersistenceManager
                    .getPersistenceManager();
            String sessionIndex = getSessionIndex(sessionId, logoutRequest, loginTenantDomain);
            /* 'SessionIndex' attribute can be optional in the SAML logout request. In that case we need to retrieve
            the session index from session Id. */
            if (sessionIndex == null) {
                sessionIndex = SSOSessionPersistenceManager.getPersistenceManager().getSessionIndexFromTokenId
                        (sessionId, loginTenantDomain);
            }
            SessionInfoData sessionInfoData = ssoSessionPersistenceManager.
                    getSessionInfo(sessionIndex, loginTenantDomain);
            issuer = getTenantAwareIssuer(issuer, sessionInfoData);

            // Replace SP's issuer value with the actual issuer value in SAML SP registry.
            String issuerQualifier = SAMLSSOUtil.getIssuerQualifier();
            if (issuerQualifier != null) {
                issuer = SAMLSSOUtil.getIssuerWithQualifier(issuer, issuerQualifier);
            }

            SAMLSSOUtil.setIssuerWithQualifierInThreadLocal(issuer);

            String subject = sessionInfoData.getSubject(issuer);
            Map<String, SAMLSSOServiceProviderDO> sessionsList = sessionInfoData.getServiceProviderList();

            SAMLSSOServiceProviderDO logoutReqIssuer = sessionsList.get(issuer);

            // Validate signature of the logout request.
            if (logoutReqIssuer.isDoValidateSignatureInRequests()) {

                // Obtaining x509 Certificate.
                setX509Certificate(issuer, logoutReqIssuer);
                validationResult = validateSignature(logoutRequest, logoutReqIssuer, subject, queryString);
                if (!validationResult.getValidationStatus()) {
                    return validationResult.getValue();
                }
            }

            SAMLSSOServiceProviderDO serviceProviderDO = sessionsList.get(issuer);
            reqValidationResponseDTO.setIssuer(serviceProviderDO.getIssuer());
            reqValidationResponseDTO.setDoSignResponse(serviceProviderDO.isDoSignResponse());
            reqValidationResponseDTO.setSigningAlgorithmUri(serviceProviderDO.getSigningAlgorithmUri());
            reqValidationResponseDTO.setDigestAlgorithmUri(serviceProviderDO.getDigestAlgorithmUri());
            if (StringUtils.isNotBlank(serviceProviderDO.getSloResponseURL())) {
                reqValidationResponseDTO.setAssertionConsumerURL(serviceProviderDO.getSloResponseURL());
            } else {
                reqValidationResponseDTO.setAssertionConsumerURL(serviceProviderDO.getAssertionConsumerUrl());
            }
            reqValidationResponseDTO.setSessionIndex(sessionIndex);
            reqValidationResponseDTO.setId(logoutRequest.getID());

            SingleLogoutMessageBuilder logoutMsgBuilder = new SingleLogoutMessageBuilder();
            LogoutResponse logoutResponse = logoutMsgBuilder.buildLogoutResponse(
                    logoutRequest.getID(),
                    SAMLSSOConstants.StatusCodes.SUCCESS_CODE,
                    null,
                    reqValidationResponseDTO.getAssertionConsumerURL(),
                    reqValidationResponseDTO.isDoSignResponse(),
                    SAMLSSOUtil.getTenantDomainFromThreadLocal(),
                    reqValidationResponseDTO.getSigningAlgorithmUri(),
                    reqValidationResponseDTO.getDigestAlgorithmUri());

            reqValidationResponseDTO.setLogoutResponse(SAMLSSOUtil.encode(SAMLSSOUtil.marshall(logoutResponse)));
            reqValidationResponseDTO.setValid(true);

            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        SAML_INBOUND_SERVICE, PROCESS_SAML_LOGOUT);
                diagnosticLogBuilder.resultMessage("Successfully processed SP initiated logout request.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .inputParam(SAMLSSOConstants.LogConstants.InputKeys.ISSUER,
                                reqValidationResponseDTO.getIssuer())
                        .inputParam(SAMLSSOConstants.LogConstants.InputKeys.CONSUMER_URL,
                                reqValidationResponseDTO.getAssertionConsumerURL());
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            return reqValidationResponseDTO;
        } catch (UserStoreException | IdentityException | IOException e) {
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        SAML_INBOUND_SERVICE, PROCESS_SAML_LOGOUT);
                diagnosticLogBuilder.resultMessage("Error processing SP initiated logout request.")
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                        .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage());
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw IdentityException.error("Error Processing the Logout Request", e);
        }
    }

    private void setX509Certificate(String issuer, SAMLSSOServiceProviderDO logoutReqIssuer) {

        try {
            SAMLSSOServiceProviderDO serviceProviderConfigs = getServiceProviderConfig(issuer,
                    logoutReqIssuer.getTenantDomain());
            if (serviceProviderConfigs != null) {
                logoutReqIssuer.setX509Certificate(serviceProviderConfigs.getX509Certificate());
            }
        } catch (IdentityException e) {
            String errorMessage = String.format("An error occurred while retrieving the application " +
                    "certificate for file based SAML service provider with the issuer name '%s'. " +
                    "The service provider will NOT be loaded.", issuer);
            log.error(errorMessage, e);
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                LoggerUtils.triggerDiagnosticLogEvent(new DiagnosticLog.DiagnosticLogBuilder(
                        SAML_INBOUND_SERVICE, PROCESS_SAML_LOGOUT)
                        .resultMessage("An error occurred while retrieving the application certificate for file " +
                                "based SAML service provider. The service provider will NOT be loaded.")
                        .inputParam(SAMLSSOConstants.LogConstants.InputKeys.ISSUER, issuer)
                        .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage())
                        .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.FAILED));
            }
        }
    }

    private String getTenantAwareIssuer(String issuer, SessionInfoData sessionInfoData) throws UserStoreException,
            IdentityException {

        String tenantDomain = null;
        if (StringUtils.isNotBlank(issuer) && issuer.contains(UserCoreConstants.TENANT_DOMAIN_COMBINER)) {
            tenantDomain = issuer.substring(issuer.lastIndexOf('@') + 1);
            issuer = issuer.substring(0, issuer.lastIndexOf('@'));
        }
        // Set the tenant domain to thread local variable if it isn't already set.
        setTenantDomainToThreadLocal(issuer, sessionInfoData, tenantDomain);
        return issuer;
    }

    /**
     * Builds the SAML error response and sets the compressed value to the reqValidationResponseDTO.
     *
     * @param id
     * @param status
     * @param statMsg
     * @param destination
     * @return
     * @throws IdentityException
     */
    private SAMLSSOReqValidationResponseDTO buildErrorResponse(String id, String status, String statMsg, String
            destination, String responseSigningAlgorithmUri, String responseDigestAlgorithmUri)
            throws IdentityException {

        SAMLSSOReqValidationResponseDTO reqValidationResponseDTO = new SAMLSSOReqValidationResponseDTO();
        LogoutResponse logoutResp = new SingleLogoutMessageBuilder().buildLogoutResponse(id, status, statMsg,
                destination, false, null, responseSigningAlgorithmUri, responseDigestAlgorithmUri);
        reqValidationResponseDTO.setLogOutReq(true);
        reqValidationResponseDTO.setValid(false);
        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(SAML_INBOUND_SERVICE, PROCESS_SAML_LOGOUT)
                    .inputParam("status code", status)
                    .inputParam("destination", destination)
                    .resultMessage(statMsg)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED);
        }
        try {
            reqValidationResponseDTO.setResponse(SAMLSSOUtil.compressResponse(SAMLSSOUtil.marshall(logoutResp)));
        } catch (IOException e) {
            if (diagnosticLogBuilder != null) {
                // diagnosticLogBuilder is null when LoggerUtils.isDiagnosticLogsEnabled() is false.
                diagnosticLogBuilder.resultMessage("Error while creating logout response.")
                        .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, e.getMessage());
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            throw IdentityException.error("Error while creating logout response", e);
        }
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return reqValidationResponseDTO;
    }

    private SAMLSSOServiceProviderDO getServiceProviderConfig(String issuer, String tenantDomain)
            throws IdentityException {

        try {
            SSOServiceProviderConfigManager stratosIdpConfigManager = SSOServiceProviderConfigManager
                    .getInstance();
            SAMLSSOServiceProviderDO ssoIdpConfigs = stratosIdpConfigManager
                    .getServiceProvider(issuer);
            if (ssoIdpConfigs == null) {
                try {
                    PrivilegedCarbonContext.startTenantFlow();
                    PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext
                            .getThreadLocalCarbonContext();
                    int tenantId = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
                    privilegedCarbonContext.setTenantId(tenantId);
                    privilegedCarbonContext.setTenantDomain(tenantDomain);
                    IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
                    ssoIdpConfigs = IdentitySAMLSSOServiceComponentHolder.getInstance().getSAMLSSOServiceProviderManager()
                            .getServiceProvider(issuer, tenantId);
                } finally {
                    PrivilegedCarbonContext.endTenantFlow();
                }
            }
            return ssoIdpConfigs;
        } catch (Exception e) {
            throw new IdentityException("Error while reading Service Provider configurations", e);
        }
    }

    private SAMLSSOReqValidationResponseDTO buildErrorResponse(String id, String status, String statMsg, String
            destination, String responseSigningAlgorithmUri, String responseDigestAlgorithmUri,
                                                               String issuer) throws IdentityException, IOException {

        SAMLSSOServiceProviderDO providerDO = getServiceProviderConfig(issuer,
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());

        SAMLSSOReqValidationResponseDTO reqValidationResponseDTO = new SAMLSSOReqValidationResponseDTO();
        LogoutResponse logoutResp = new SingleLogoutMessageBuilder().buildLogoutResponse(id, status, statMsg,
                destination, false, null, responseSigningAlgorithmUri, responseDigestAlgorithmUri);
        reqValidationResponseDTO.setLogOutReq(true);
        reqValidationResponseDTO.setValid(false);
        reqValidationResponseDTO.setResponse(SAMLSSOUtil.compressResponse(SAMLSSOUtil.marshall(logoutResp)));
        if (providerDO != null) {
            // use only default default ACS
            if (StringUtils.isNotBlank(providerDO.getSloResponseURL())) {
                reqValidationResponseDTO.setAssertionConsumerURL(providerDO.getSloResponseURL());
            }
            if (StringUtils.isNotBlank(providerDO.getAssertionConsumerUrl())) {
                reqValidationResponseDTO.setAssertionConsumerURL(providerDO.getAssertionConsumerUrl());
            } else {
                reqValidationResponseDTO.setAssertionConsumerURL(providerDO.getDefaultAssertionConsumerUrl());
            }
            reqValidationResponseDTO.setIssuer(issuer);
        }
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SAML_INBOUND_SERVICE, PROCESS_SAML_LOGOUT);
            diagnosticLogBuilder.resultMessage("Error while processing the SAML logout request.")
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.FAILED)
                    .inputParam(SAMLSSOConstants.LogConstants.InputKeys.ISSUER, reqValidationResponseDTO.getIssuer())
                    .inputParam(SAMLSSOConstants.LogConstants.InputKeys.CONSUMER_URL,
                            reqValidationResponseDTO.getAssertionConsumerURL())
                    .inputParam(LogConstants.InputKeys.ERROR_MESSAGE, statMsg)
                    .inputParam("status code", status);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return reqValidationResponseDTO;
    }

    private ValidationResult<SAMLSSOReqValidationResponseDTO> validateLogoutRequest(LogoutRequest logoutRequest) {

        ValidationResult<SAMLSSOReqValidationResponseDTO> validationResult = new ValidationResult<>();
        validationResult.setValidationStatus(true);

        if (logoutRequest == null) {
            SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = new SAMLSSOReqValidationResponseDTO();
            samlssoReqValidationResponseDTO.setLogOutReq(true);
            validationResult.setValue(samlssoReqValidationResponseDTO);
            validationResult.setValidationStatus(false);
        }

        return validationResult;
    }

    private ValidationResult<SAMLSSOReqValidationResponseDTO> validateIssuer(LogoutRequest logoutRequest)
            throws IdentityException {

        ValidationResult<SAMLSSOReqValidationResponseDTO> validationResult = new ValidationResult<>();
        validationResult.setValidationStatus(true);

        if (logoutRequest.getIssuer() == null) {
            String message = "Issuer should be mentioned in the Logout Request";
            log.error(message);
            validationResult.setValue(buildErrorResponse(logoutRequest.getID(),
                    SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, message, logoutRequest.getDestination(),
                    defaultSigningAlgoUri, defaultDigestAlgoUri));
            validationResult.setValidationStatus(false);
        } else if (logoutRequest.getIssuer().getValue() == null) {
            String message = "Issuer value cannot be null in the Logout Request";
            log.error(message);
            validationResult.setValue(buildErrorResponse(logoutRequest.getID(),
                    SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, message, logoutRequest.getDestination(),
                    defaultSigningAlgoUri, defaultDigestAlgoUri));
            validationResult.setValidationStatus(false);
        }

        return validationResult;
    }

    private ValidationResult<SAMLSSOReqValidationResponseDTO> validateSubject(LogoutRequest logoutRequest)
            throws IOException, IdentityException {

        String issuer = logoutRequest.getIssuer().getValue();
        ValidationResult<SAMLSSOReqValidationResponseDTO> validationResult = new ValidationResult<>();
        validationResult.setValidationStatus(true);

        if (logoutRequest.getNameID() == null && logoutRequest.getBaseID() == null
                && logoutRequest.getEncryptedID() == null) {
            String message = "Subject Name should be specified in the Logout Request";
            log.error(message);

            validationResult.setValue(buildErrorResponse(logoutRequest.getID(),
                    SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, message, logoutRequest.getDestination(),
                    defaultSigningAlgoUri, defaultDigestAlgoUri, issuer));
            validationResult.setValidationStatus(false);
        }

        return validationResult;
    }

    private ValidationResult<SAMLSSOReqValidationResponseDTO> validatePrincipleSession(String sessionId,
                                                                                       LogoutRequest logoutRequest,
                                                                                       String loginTenantDomain)
            throws IOException, IdentityException {

        String issuer = logoutRequest.getIssuer().getValue();
        ValidationResult<SAMLSSOReqValidationResponseDTO> validationResult = new ValidationResult<>();
        validationResult.setValidationStatus(true);

        if ((logoutRequest.getSessionIndexes() == null || logoutRequest.getSessionIndexes().isEmpty()) &&
                StringUtils.isBlank(sessionId)) {
            String message = "Session index should be present in the logout request or in request cookies.";
            validationResult.setValue(buildErrorResponse(logoutRequest.getID(),
                    SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, message, logoutRequest.getDestination(),
                    defaultSigningAlgoUri, defaultDigestAlgoUri,
                    issuer));
            validationResult.setValidationStatus(false);
            log.error(message);
            return validationResult;
        }

        String sessionIndex = getSessionIndex(sessionId, logoutRequest, loginTenantDomain);

        if (StringUtils.isBlank(sessionIndex)) {
            String message = "Error while retrieving the Session Index ";
            log.error("Error in retrieving sessionIndex : " + sessionIndex);
            SAMLSSOReqValidationResponseDTO reqValidationResponseDTO = buildErrorResponse(logoutRequest.getID(),
                    SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, message, null, defaultSigningAlgoUri,
                    defaultDigestAlgoUri, issuer);
            reqValidationResponseDTO.setLogoutFromAuthFramework(true);
            validationResult.setValue(reqValidationResponseDTO);
            validationResult.setValidationStatus(false);
        }

        SSOSessionPersistenceManager ssoSessionPersistenceManager =
                SSOSessionPersistenceManager.getPersistenceManager();
        SessionInfoData sessionInfoData = ssoSessionPersistenceManager.getSessionInfo(sessionIndex, loginTenantDomain);

        if (sessionInfoData == null) {
            String message = "No Established Sessions corresponding to Session Indexes provided.";
            log.error(message);
            SAMLSSOReqValidationResponseDTO reqValidationResponseDTO = buildErrorResponse(logoutRequest.getID(),
                    SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, message, null, defaultSigningAlgoUri,
                    defaultDigestAlgoUri, issuer);
            reqValidationResponseDTO.setLogoutFromAuthFramework(true);
            validationResult.setValue(reqValidationResponseDTO);
            validationResult.setValidationStatus(false);
        }

        return validationResult;
    }

    private ValidationResult<SAMLSSOReqValidationResponseDTO> validateSignature(
            LogoutRequest logoutRequest, SAMLSSOServiceProviderDO logoutReqIssuer, String subject, String queryString)
            throws IdentityException, IOException {

        String issuer = logoutRequest.getIssuer().getValue();
        ValidationResult<SAMLSSOReqValidationResponseDTO> validationResult = new ValidationResult<>();
        validationResult.setValidationStatus(true);

        // Validate 'Destination'
        List<String> idpUrlSet = SAMLSSOUtil.getDestinationFromTenantDomain(SAMLSSOUtil
                .getTenantDomainFromThreadLocal());

        if (logoutRequest.getDestination() == null
                || !idpUrlSet.contains(logoutRequest.getDestination())) {
            String message = "Destination validation for Logout Request failed. " +
                    "Received: [" + logoutRequest.getDestination() +
                    "]." + " Expected: [" + StringUtils.join(idpUrlSet, ',') + "]";
            log.error(message);
            validationResult.setValue(buildErrorResponse(logoutRequest.getID(), SAMLSSOConstants.StatusCodes
                    .REQUESTOR_ERROR, message, logoutRequest.getDestination(), logoutReqIssuer
                    .getSigningAlgorithmUri(), logoutReqIssuer.getDigestAlgorithmUri(), issuer));
            validationResult.setValidationStatus(false);
        }

        if (!SAMLSSOUtil.validateLogoutRequestSignature(logoutRequest, logoutReqIssuer.getX509Certificate(),
                queryString)) {
            String message = "Signature validation for Logout Request failed";
            log.error(message);
            validationResult.setValue(buildErrorResponse(logoutRequest.getID(), SAMLSSOConstants.StatusCodes
                    .REQUESTOR_ERROR, message, logoutRequest.getDestination(), logoutReqIssuer
                    .getSigningAlgorithmUri(), logoutReqIssuer.getDigestAlgorithmUri()));
            validationResult.setValidationStatus(false);
        }

        return validationResult;
    }

    private void setTenantDomainToThreadLocal(String issuer, SessionInfoData sessionInfoData, String tenantDomain)
            throws UserStoreException, IdentityException {

        if (IdentityUtil.isBlank(SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
            if (StringUtils.isNotBlank(issuer) && StringUtils.isNotBlank(tenantDomain)) {
                SAMLSSOUtil.setTenantDomainInThreadLocal(tenantDomain);
                if (log.isDebugEnabled()) {
                    log.debug("Tenant Domain: " + tenantDomain + " & Issuer name: " + issuer + "has been " +
                            "split");
                }
            } else {
                SAMLSSOServiceProviderDO serviceProvider = sessionInfoData.getServiceProviderList().get(issuer);
                if (serviceProvider != null) {
                    SAMLSSOUtil.setTenantDomainInThreadLocal(serviceProvider.getTenantDomain());
                } else {
                    throw IdentityException.error("Service provider :" + issuer + " does not exist in session " +
                            "info data.");
                }
            }
        }
    }

    private String getSessionIndex(String sessionId, LogoutRequest logoutRequest, String loginTenantDomain) {

        SSOSessionPersistenceManager ssoSessionPersistenceManager =
                SSOSessionPersistenceManager.getPersistenceManager();
        if (!logoutRequest.getSessionIndexes().isEmpty()) {
            return logoutRequest.getSessionIndexes().get(0).getSessionIndex();
        }
        return ssoSessionPersistenceManager.getSessionIndexFromTokenId(sessionId, loginTenantDomain);
    }
}
