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

package org.wso2.carbon.identity.sso.saml.servlet;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.core.xml.XMLObject;
import org.owasp.encoder.Encode;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.SameSiteCookie;
import org.wso2.carbon.core.ServletCookie;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionAuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationContextProperty;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthRequestWrapper;
import org.wso2.carbon.identity.application.authentication.framework.model.CommonAuthResponseWrapper;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.model.IdentityCookieConfig;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.FrontChannelSLOParticipantInfo;
import org.wso2.carbon.identity.sso.saml.FrontChannelSLOParticipantStore;
import org.wso2.carbon.identity.sso.saml.SAMLECPConstants;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SAMLSSOService;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.sso.saml.builders.SingleLogoutMessageBuilder;
import org.wso2.carbon.identity.sso.saml.builders.X509CredentialImpl;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCache;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCacheKey;
import org.wso2.carbon.identity.sso.saml.cache.SessionDataCache;
import org.wso2.carbon.identity.sso.saml.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.sso.saml.common.SAMLSSOProviderConstants;
import org.wso2.carbon.identity.sso.saml.dto.QueryParamDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSORespDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOSessionDTO;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ClientException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponent;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponentHolder;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.session.SessionInfoData;
import org.wso2.carbon.identity.sso.saml.util.SAMLSOAPUtils;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.idp.mgt.util.IdPManagementUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.MediaType;
import javax.xml.soap.SOAPException;
import javax.xml.transform.TransformerException;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.RequestParams.TENANT_DOMAIN;
import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.LogConstants.ActionIDs.HAND_OVER_TO_FRAMEWORK;
import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.LogConstants.ActionIDs.PROCESS_SAML_REQUEST;
import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.LogConstants.ActionIDs.VALIDATE_SAML_REQUEST;
import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.LogConstants.SAML_INBOUND_SERVICE;

/**
 * This is the entry point for authentication process in an SSO scenario. This servlet is registered
 * with the URL pattern /samlsso and act as the control servlet. The message flow of an SSO scenario
 * is as follows.
 * <ol>
 * <li>SP sends a SAML Request via HTTP POST to the https://<ip>:<port>/samlsso endpoint.</li>
 * <li>IdP validates the SAML Request and checks whether this user is already authenticated.</li>
 * <li>If the user is authenticated, it will generate a SAML Response and send it back the SP via
 * the samlsso_redirect_ajaxprocessor.jsp.</li>
 * <li>If the user is not authenticated, it will send him to the login page and prompts user to
 * enter his credentials.</li>
 * <li>If these credentials are valid, then the user will be redirected back the SP with a valid
 * SAML Assertion. If not, he will be prompted again for credentials.</li>
 * </ol>
 */
public class SAMLSSOProviderServlet extends HttpServlet {

    private static final long serialVersionUID = -5182312441482721905L;
    private static final Log log = LogFactory.getLog(SAMLSSOProviderServlet.class);

    private SAMLSSOService samlSsoService = new SAMLSSOService();

    private static final String SAML_SSO_TOKEN_ID_COOKIE = "samlssoTokenId";
    private static final String ACR_VALUES_ATTRIBUTE = "acr_values";
    private static final String REQUEST_PARAM_SP = "sp";
    private static final String HTTPS_SCHEME = "https";
    private static final String HTTP_SCHEME = "http";

    private static final boolean SAML_ECP_ENABLED = false;
    private static final int DEFAULT_HTTPS_PORT = 443;
    private static final int DEFAULT_HTTP_PORT = 80;

    private static final String formPostPageTemplate = "<html>\n" +
            "<body onload=\"javascript:document.getElementById('samlsso-response-form').submit()\">\n" +
            "<h2>Please wait while we take you back to $app</h2>\n" +
            "<p><a href=\"javascript:document.getElementById('samlsso-response-form').submit()\">Click here</a>" +
            " if you have been waiting for too long.</p>\n" +
            "<form id=\"samlsso-response-form\" method=\"post\" action=\"$acUrl\">\n" +
            "    <!--$params-->\n" +
            "    <!--$additionalParams-->\n" +
            "</form>\n" +
            "</body>\n" +
            "</html>";

    @Override
    protected void doGet(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse) throws ServletException, IOException {
        try {
            handleRequest(httpServletRequest, httpServletResponse, false);
        } finally {
            SAMLSSOUtil.removeSaaSApplicationThreaLocal();
            SAMLSSOUtil.removeUserTenantDomainThreaLocal();
            SAMLSSOUtil.removeTenantDomainFromThreadLocal();
            SAMLSSOUtil.removeIssuerWithQualifierInThreadLocal();
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            handleRequest(req, resp, true);
        } finally {
            SAMLSSOUtil.removeSaaSApplicationThreaLocal();
            SAMLSSOUtil.removeUserTenantDomainThreaLocal();
            SAMLSSOUtil.removeTenantDomainFromThreadLocal();
            SAMLSSOUtil.removeIssuerWithQualifierInThreadLocal();
        }
    }

    /**
     * All requests are handled by this handleRequest method. In case of SAMLRequest the user
     * will be redirected to commonAuth servlet for authentication. Based on successful
     * authentication of the user a SAMLResponse is sent back to service provider.
     * In case of logout requests, the IDP will send logout requests
     * to the other session participants and then send the logout response back to the initiator.
     *
     * @param req
     * @param resp
     * @throws ServletException
     * @throws IOException
     */
    private void handleRequest(HttpServletRequest req, HttpServletResponse resp, boolean isPost)
            throws ServletException, IOException {

        String sessionId = null;
        Cookie ssoTokenIdCookie = getTokenIdCookie(req);

        if (ssoTokenIdCookie != null) {
            sessionId = ssoTokenIdCookie.getValue();
        }

        String queryString = req.getQueryString();
        if (log.isDebugEnabled()) {
            log.debug("Query string : " + queryString);
        }
        // if an openid authentication or password authentication
        String authMode = req.getParameter(SAMLSSOConstants.AUTH_MODE);
        if (!SAMLSSOConstants.AuthnModes.OPENID.equals(authMode)) {
            authMode = SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD;
        }
        String relayState = req.getParameter(SAMLSSOConstants.RELAY_STATE);
        String spEntityID = req.getParameter(SAMLSSOConstants.QueryParameter
                .SP_ENTITY_ID.toString());
        String samlRequest = req.getParameter(SAMLSSOConstants.SAML_REQUEST);
        String samlResponse = req.getParameter(SAMLSSOConstants.SAML_RESP);
        String sessionDataKey = getSessionDataKey(req);
        String slo = req.getParameter(SAMLSSOConstants.QueryParameter.SLO.toString());
        Object flowStatus = req.getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);

        try {

            //TODO add debug log istocommonth and flowstatus
            String isToCommonOauth = req.getParameter(FrameworkConstants.RequestParams.TO_COMMONAUTH);
            if ("true".equals(isToCommonOauth) && flowStatus == null) {
                sendRequestToFramework(req, resp);
                return;
            }

            String tenantDomain = null;
            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                tenantDomain = IdentityTenantUtil.getTenantDomainFromContext();
                if (log.isDebugEnabled()) {
                    log.debug("Tenant domain from context: " + tenantDomain);
                }
            }

            if (StringUtils.isBlank(tenantDomain)) {
                tenantDomain = req.getParameter(MultitenantConstants.TENANT_DOMAIN);
                if (log.isDebugEnabled()) {
                    log.debug("Tenant domain not available in context. Tenant domain from query param: " +
                            tenantDomain);
                }
            }

            SAMLSSOUtil.setTenantDomainInThreadLocal(tenantDomain);

            String issuerQualifier = req.getParameter(SAMLSSOConstants.INBOUND_ISSUER_QUALIFIER);
            SAMLSSOUtil.setIssuerQualifier(issuerQualifier);

            if (sessionDataKey != null) { //Response from common authentication framework.
                SAMLSSOSessionDTO sessionDTO = getSessionDataFromCache(sessionDataKey);

                if (sessionDTO != null) {
                    setSPAttributeToRequest(req, sessionDTO.getIssuer(), sessionDTO.getTenantDomain());
                    SAMLSSOUtil.setTenantDomainInThreadLocal(sessionDTO.getTenantDomain());
                    SAMLSSOUtil.setIssuerWithQualifierInThreadLocal(sessionDTO.getIssuer());
                    if (sessionDTO.isInvalidLogout()) {
                        String queryParams = "?" + SAMLSSOConstants.STATUS + "=" + URLEncoder.
                                encode(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                                        "UTF-8") + "&" + SAMLSSOConstants.STATUS_MSG + "=" + URLEncoder.encode
                                ("Invalid Logout Request", "UTF-8");

                        String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                                .REQUESTOR_ERROR, "Invalid Logout Request", null);
                        String acsUrl = sessionDTO.getAssertionConsumerURL();//sessionDTO.getValidationRespDTO()

                        if (errorResp != null) {
                            queryParams += "&" + SAMLSSOConstants.LOGOUT_RESP + "=" + URLEncoder.encode(errorResp,
                                    "UTF-8");
                        }

                        if (acsUrl != null) {
                            queryParams += "&" + SAMLSSOConstants.ASSRTN_CONSUMER_URL + "=" + URLEncoder.encode
                                    (acsUrl, "UTF-8");
                        }

                        log.warn("Redirecting to default logout page due to an invalid logout request");
                        String defaultLogoutLocation = SAMLSSOUtil.getDefaultLogoutEndpoint();
                        resp.sendRedirect(FrameworkUtils.getRedirectURL(defaultLogoutLocation + queryParams, req));
                    } else if (sessionDTO.isLogoutReq()) {
                        handleLogoutResponseFromFramework(req, resp, sessionDTO);
                    } else {
                        handleAuthenticationReponseFromFramework(req, resp, sessionId, sessionDTO);
                    }

                    removeAuthenticationResult(req, sessionDataKey);

                } else {
                    log.error("Failed to retrieve sessionDTO from the cache for key " + sessionDataKey);
                    String errorResp = SAMLSSOUtil.buildErrorResponse(
                            SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR,
                            SAMLSSOConstants.Notification.EXCEPTION_STATUS, null);
                    sendNotification(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                            SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, null, req, resp);
                    return;
                }
            } else if (spEntityID != null || slo != null) { // idp initiated SSO/SLO
                handleIdPInitSSO(req, resp, relayState, queryString, authMode, sessionId, isPost, (slo != null));
            } else if (samlRequest != null) {// SAMLRequest received. SP initiated SSO
                handleSPInitSSO(req, resp, queryString, relayState, authMode, samlRequest, sessionId, isPost);
            } else if (samlResponse != null) {// SAMLResponse received.
                handleSAMLResponse(req, resp, samlResponse, sessionId, isPost);
            } else {
                handleInvalidRequestMessage(req, resp, sessionId);
            }
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while handling SAML2 SSO request", e);
            }
            String errorResp = null;
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR,
                        "Error occurred while handling SAML2 SSO request", null);
            } catch (IdentityException e1) {
                log.error("Error while building SAML response", e1);
            }
            sendNotification(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, null, req, resp);
        } catch (IdentitySAML2ClientException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred due to an invalid SAML2 SSO request.", e);
            }
            String errorResp = null;
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR,
                        "Error occurred due to an invalid SAML2 SSO request.", null);
            } catch (IdentityException e1) {
                log.error("Error while building SAML response", e1);
            }
            sendNotification(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, null, req, resp);
        } catch (IdentityException e) {
            log.error("Error when processing the authentication request!", e);
            String errorResp = null;
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR,
                        "Error when processing the authentication request", null);
            } catch (IdentityException e1) {
                log.error("Error while building SAML response", e1);
            }
            sendNotification(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, null, req, resp);
        }
    }

    private void handleInvalidRequestMessage(HttpServletRequest req, HttpServletResponse resp, String sessionId)
            throws IOException, IdentityException, ServletException {

        if (log.isDebugEnabled()) {
            log.debug("An invalid request message or single logout message received with session id : " + sessionId);
        }

        if (sessionId == null) {
            String errorResp = SAMLSSOUtil.buildErrorResponse(
                    SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                    "Invalid request message", null);
            sendNotification(errorResp, SAMLSSOConstants.Notification.INVALID_MESSAGE_STATUS,
                    SAMLSSOConstants.Notification.INVALID_MESSAGE_MESSAGE, null, req, resp);
        } else {
            // Non-SAML request are assumed to be logout requests.
            sendToFrameworkForLogout(req, resp, null, null, sessionId, true,
                    false);
        }
    }

    private void handleSAMLResponse(HttpServletRequest req, HttpServletResponse resp, String samlResponse,
                                    String sessionId, boolean isPost)
            throws IdentityException, IOException, ServletException {

        XMLObject response;

        if (isPost) {
            response = SAMLSSOUtil.unmarshall(SAMLSSOUtil.decodeForPost(samlResponse));
        } else {
            response = SAMLSSOUtil.unmarshall(SAMLSSOUtil.decode(samlResponse));
        }

        if (response instanceof LogoutResponse) {
            LogoutResponse logoutResponse = (LogoutResponse) response;
            handleLogoutResponseFromSP(req, resp, sessionId, logoutResponse);
        } else {
            handleInvalidRequestMessage(req, resp, sessionId);
        }
    }

    private void handleLogoutResponseFromSP(HttpServletRequest req, HttpServletResponse resp, String sessionId,
                                            LogoutResponse logoutResponse)
            throws ServletException, IdentityException, IOException {

        String inResponseToId = logoutResponse.getInResponseTo();
        FrontChannelSLOParticipantInfo frontChannelSLOParticipantInfo =
                getFrontChannelSLOParticipantInfo(inResponseToId);
        String loggedInTenantDomain = getLoggedInTenantDomain(req);

        if (frontChannelSLOParticipantInfo == null || !frontChannelSLOParticipantInfo.
                getCurrentSLOInvokedParticipant().equals(logoutResponse.getIssuer().getValue())) {
            handleInvalidRequestMessage(req, resp, sessionId);
        } else {
            // Remove front-channel SLO Participant info from the FrontChannelSLOParticipantStore.
            removeFrontChannelSLOParticipantInfo(inResponseToId);
            String logoutResponseIssuer = logoutResponse.getIssuer().getValue();
            SAMLSSOServiceProviderDO responseIssuerSP = SAMLSSOUtil.getSPConfig(
                    SAMLSSOUtil.getTenantDomainFromThreadLocal(), logoutResponseIssuer);

            boolean isSuccessfullyLogout = SAMLSSOUtil.validateLogoutResponse(logoutResponse,
                    responseIssuerSP.getCertAlias(), responseIssuerSP.getTenantDomain());

            if (!isSuccessfullyLogout) {
                log.warn("Redirecting to default logout page due to an invalid logout response.");
                resp.sendRedirect(FrameworkUtils.getRedirectURL(SAMLSSOUtil.getDefaultLogoutEndpoint(), req));
                if (log.isDebugEnabled()) {
                    log.debug("Single logout failed due to failure in logout response validation for logout " +
                            "response issuer: " + logoutResponseIssuer);
                }
            } else {
                removeSPFromSession(frontChannelSLOParticipantInfo.getSessionIndex(), logoutResponseIssuer,
                        loggedInTenantDomain);

                List<SAMLSSOServiceProviderDO> samlssoServiceProviderDOList =
                        SAMLSSOUtil.getRemainingSessionParticipantsForSLO(
                                frontChannelSLOParticipantInfo.getSessionIndex(),
                                frontChannelSLOParticipantInfo.getOriginalLogoutRequestIssuer(),
                                frontChannelSLOParticipantInfo.isIdPInitSLO(), loggedInTenantDomain);

                if (samlssoServiceProviderDOList.isEmpty()) {
                    respondToOriginalLogoutRequestIssuer(req, resp, sessionId, frontChannelSLOParticipantInfo);
                } else {
                    sendLogoutRequestToSessionParticipant(req, resp, samlssoServiceProviderDOList,
                            frontChannelSLOParticipantInfo.getOriginalIssuerLogoutRequestId(),
                            frontChannelSLOParticipantInfo.isIdPInitSLO(),
                            frontChannelSLOParticipantInfo.getRelayState(),
                            frontChannelSLOParticipantInfo.getReturnToURL(),
                            frontChannelSLOParticipantInfo.getSessionIndex(),
                            frontChannelSLOParticipantInfo.getOriginalLogoutRequestIssuer(), loggedInTenantDomain);
                }
            }
        }
    }

    /**
     * Respond back to the original logout request issuer after handling all the front-channel enabled
     * session participants.
     *
     * @param req                            HttpServlet Request.
     * @param resp                           HttpServlet Response.
     * @param sessionId                      Session id.
     * @param frontChannelSLOParticipantInfo Front-Channel SLO Participant Information.
     * @throws IOException       If sending response fails.
     * @throws IdentityException If building logout response fails.
     * @throws ServletException  If sending response fails.
     */
    private void respondToOriginalLogoutRequestIssuer(HttpServletRequest req, HttpServletResponse resp,
                                                      String sessionId,
                                                      FrontChannelSLOParticipantInfo frontChannelSLOParticipantInfo)
            throws IOException, IdentityException, ServletException {

        if (SSOSessionPersistenceManager.getSessionIndexFromCache(sessionId, getLoggedInTenantDomain(req)) == null) {
            // Remove tokenId Cookie when there is no session available.
            removeTokenIdCookie(req, resp, getLoggedInTenantDomain(req));
        }

        if (frontChannelSLOParticipantInfo.isIdPInitSLO()) {
            // Redirecting to the return URL or IS logout page.
            resp.sendRedirect(frontChannelSLOParticipantInfo.getReturnToURL());
        } else {
            SAMLSSOServiceProviderDO originalIssuer =
                    SAMLSSOUtil.getSPConfig(SAMLSSOUtil.getTenantDomainFromThreadLocal(),
                            frontChannelSLOParticipantInfo.getOriginalLogoutRequestIssuer());
            LogoutResponse logoutResponse = buildLogoutResponseForOriginalIssuer(
                    frontChannelSLOParticipantInfo.getOriginalIssuerLogoutRequestId(), originalIssuer);

            // Sending LogoutResponse back to the original issuer.
            sendResponse(req, resp, frontChannelSLOParticipantInfo.getRelayState(),
                    SAMLSSOUtil.encode(SAMLSSOUtil.marshall(logoutResponse)),
                    logoutResponse.getDestination(), null, null,
                    SAMLSSOUtil.getTenantDomainFromThreadLocal());
        }
    }

    /**
     * Build logout response for the original logout request issuer.
     *
     * @param originalIssuerLogoutRequestId Logout request id of original issuer.
     * @param originalIssuer                Original issuer.
     * @return Logout response.
     * @throws IdentityException If building logout response fails.
     */
    private LogoutResponse buildLogoutResponseForOriginalIssuer(String originalIssuerLogoutRequestId,
                                                                SAMLSSOServiceProviderDO originalIssuer)
            throws IdentityException {

        String destination;
        if (StringUtils.isNotBlank(originalIssuer.getSloResponseURL())) {
            destination = originalIssuer.getSloResponseURL();
            if (log.isDebugEnabled()) {
                log.debug("Destination of the logout response is set to the SLO response URL of the SP: " +
                        originalIssuer.getSloResponseURL());
            }
        } else {
            destination = originalIssuer.getDefaultAssertionConsumerUrl();
            if (log.isDebugEnabled()) {
                log.debug("Destination of the logout response is set to the ACS URL of the SP: " +
                        originalIssuer.getAssertionConsumerUrl());
            }
        }

        SingleLogoutMessageBuilder logoutMsgBuilder = new SingleLogoutMessageBuilder();
        LogoutResponse logoutResponse = logoutMsgBuilder.buildLogoutResponse(
                originalIssuerLogoutRequestId,
                SAMLSSOConstants.StatusCodes.SUCCESS_CODE,
                null,
                destination,
                originalIssuer.isDoSignResponse(),
                SAMLSSOUtil.getTenantDomainFromThreadLocal(),
                originalIssuer.getSigningAlgorithmUri(),
                originalIssuer.getDigestAlgorithmUri());

        return logoutResponse;
    }

    private void removeSPFromSession(String sessionIndex, String serviceProvider, String loginTenantDomain) {

        if (sessionIndex != null && serviceProvider != null) {
            SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey(sessionIndex);
            SAMLSSOParticipantCacheEntry cacheEntry = SAMLSSOParticipantCache.getInstance().
                    getValueFromCache(cacheKey, loginTenantDomain);

            SessionInfoData sessionInfoData = cacheEntry.getSessionInfoData();
            if (sessionInfoData != null && sessionInfoData.getServiceProviderList() != null) {
                sessionInfoData.removeServiceProvider(serviceProvider);
                SSOSessionPersistenceManager.addSessionInfoDataToCache(sessionIndex, sessionInfoData, loginTenantDomain);
            }
        }
    }

    /**
     * In federated and multi steps scenario there is a redirection from commonauth to samlsso so have to get
     * session data key from query parameter
     *
     * @param req Http servlet request
     * @return Session data key
     */
    private String getSessionDataKey(HttpServletRequest req) {
        String sessionDataKey = (String) req.getAttribute(SAMLSSOConstants.SESSION_DATA_KEY);
        if (sessionDataKey == null) {
            sessionDataKey = req.getParameter(SAMLSSOConstants.SESSION_DATA_KEY);
        }
        return sessionDataKey;
    }

    /**
     * Prompts user a notification with the status and message
     *
     * @param req
     * @param resp
     * @throws ServletException
     * @throws IOException
     */
    private void sendNotification(String errorResp, String status, String message,
                                  String acUrl, HttpServletRequest req,
                                  HttpServletResponse resp) throws ServletException, IOException {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                SAML_INBOUND_SERVICE, VALIDATE_SAML_REQUEST);
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder.resultMessage("An error occurred while processing the SAML request. Prompts user " +
                            "a notification.")
            .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
            .resultStatus(DiagnosticLog.ResultStatus.FAILED)
            .inputParam(SAMLSSOConstants.LogConstants.InputKeys.ASSERTION_URL, acUrl)
            .inputParam("status", status)
            .inputParam("status message", message)
            .inputParam("error response", errorResp);
        }
        if (isSAMLECPRequest(req)) {
            sendNotificationForECPRequest(resp, errorResp, acUrl);
        } else {
            String redirectURL = SAMLSSOUtil.getNotificationEndpoint();

            //TODO Send status codes rather than full messages in the GET request
            String queryParams = "?" + SAMLSSOConstants.STATUS + "=" + URLEncoder.encode(status, "UTF-8") +
                    "&" + SAMLSSOConstants.STATUS_MSG + "=" + URLEncoder.encode(message, "UTF-8");

            if (errorResp != null) {
                queryParams += "&" + SAMLSSOConstants.SAML_RESP + "=" + URLEncoder.encode(errorResp, "UTF-8");
            }

            // If the assertion consumer url is null, get it from the session.
            if (StringUtils.isBlank(acUrl)) {
                String sessionDataKey = getSessionDataKey(req);
                SAMLSSOSessionDTO sessionDTO = null;
                if (StringUtils.isNotBlank(sessionDataKey)) {
                    sessionDTO = getSessionDataFromCache(sessionDataKey);
                }
                if (sessionDTO != null) {
                    acUrl = sessionDTO.getAssertionConsumerURL();
                }
            }

            if (StringUtils.isNotBlank(acUrl)) {
                queryParams += "&" + SAMLSSOConstants.ASSRTN_CONSUMER_URL + "=" +
                        URLEncoder.encode(acUrl, SAMLSSOConstants.ENCODING_FORMAT);
            }

            String relayState = req.getParameter(SAMLSSOConstants.RELAY_STATE);
            // If the request doesn't have a relay state, get it from the session.
            if (StringUtils.isEmpty(relayState)) {
                String sessionDataKey = getSessionDataKey(req);
                SAMLSSOSessionDTO sessionDTO = null;
                if (StringUtils.isNotEmpty(sessionDataKey)) {
                    sessionDTO = getSessionDataFromCache(sessionDataKey);
                }
                if (sessionDTO != null) {
                    relayState = sessionDTO.getRelayState();
                }
            }

            if (StringUtils.isNotEmpty(relayState)) {
                queryParams += "&" + SAMLSSOConstants.RELAY_STATE + "=" +
                        URLEncoder.encode(relayState, SAMLSSOConstants.ENCODING_FORMAT);
            }

            String queryAppendedUrl = FrameworkUtils.appendQueryParamsStringToUrl(redirectURL, queryParams);
            resp.sendRedirect(FrameworkUtils.getRedirectURL(queryAppendedUrl, req));
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                diagnosticLogBuilder.inputParam(LogConstants.InputKeys.REDIREDCT_URI, redirectURL);
            }
        }
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
    }

    private void handleIdPInitSSO(HttpServletRequest req, HttpServletResponse resp, String relayState,
                                  String queryString, String authMode, String sessionId,
                                  boolean isPost, boolean isLogout) throws UserStoreException, IdentityException,
                                                                      IOException, ServletException {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(SAML_INBOUND_SERVICE, PROCESS_SAML_REQUEST);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(SAMLSSOConstants.LogConstants.InputKeys.QUERY_STRING, queryString);
            if (isLogout) {
                diagnosticLogBuilder.resultMessage("Handling IdP Initiated SLO request.");
            } else {
                diagnosticLogBuilder.resultMessage("Handling IdP Initiated SSO request.");
            }
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        String rpSessionId = req.getParameter(MultitenantConstants.SSO_AUTH_SESSION_ID);
        SAMLSSOService samlSSOService = new SAMLSSOService();

        String defaultLogoutLocation = FrameworkUtils.getRedirectURL(SAMLSSOUtil.getDefaultLogoutEndpoint(), req);
        SAMLSSOReqValidationResponseDTO signInRespDTO = samlSSOService.validateIdPInitSSORequest(
                relayState, queryString, getQueryParams(req), defaultLogoutLocation, sessionId, rpSessionId,
                authMode, isLogout, getLoggedInTenantDomain(req));
        setSPAttributeToRequest(req, signInRespDTO.getIssuer(), SAMLSSOUtil.getTenantDomainFromThreadLocal());

        if (!signInRespDTO.isLogOutReq()) {
            if (signInRespDTO.isValid()) {
                sendToFrameworkForAuthentication(req, resp, signInRespDTO, relayState, false);
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("Invalid IdP initiated SAML SSO Request");
                }

                String errorResp = signInRespDTO.getResponse();
                String acsUrl = signInRespDTO.getAssertionConsumerURL();
                if (StringUtils.isBlank(acsUrl)) {
                    String issuer = signInRespDTO.getIssuer();

                    if (StringUtils.isBlank(issuer) && req.getParameter("spEntityID") != null) {
                        issuer = req.getParameter("spEntityID");
                    }
                    if (StringUtils.isNotBlank(issuer)) {
                        SAMLSSOServiceProviderDO serviceProviderDO =
                                SAMLSSOUtil.getSPConfig(SAMLSSOUtil.getTenantDomainFromThreadLocal(),
                                SAMLSSOUtil.splitAppendedTenantDomain(issuer));

                        if (serviceProviderDO != null) {
                            // if ACS is not available in request, priority should be given to SLO response URL over
                            // default ACS in sp config.
                            acsUrl = serviceProviderDO.getSloResponseURL();
                            if (StringUtils.isBlank(acsUrl)) {
                                acsUrl = serviceProviderDO.getDefaultAssertionConsumerUrl();
                            }
                        }
                    }
                }
                sendNotification(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                                 SAMLSSOConstants.Notification.EXCEPTION_MESSAGE,
                                 acsUrl, req, resp);
            }
        } else {
            if(signInRespDTO.isValid()) {
                sendToFrameworkForLogout(req, resp, signInRespDTO, relayState, sessionId, false, isPost);
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("Invalid IdP initiated SAML Single Logout Request");
                }

                if (signInRespDTO.isLogoutFromAuthFramework()) {
                    sendToFrameworkForLogout(req, resp, null, null, sessionId, true, isPost);
                } else {
                    String errorResp = signInRespDTO.getResponse();
                    String acsUrl = signInRespDTO.getAssertionConsumerURL();
                    if (StringUtils.isBlank(acsUrl)) {
                        String issuer = signInRespDTO.getIssuer();
                        String returnToUrl = signInRespDTO.getReturnToURL();

                        if (StringUtils.isBlank(issuer) && req.getParameter("spEntityID") != null) {
                            issuer = req.getParameter("spEntityID");
                        }
                        if (StringUtils.isBlank(returnToUrl) && req.getParameter("returnTo") != null) {
                            returnToUrl = req.getParameter("returnTo");
                        }
                        if (StringUtils.isNotBlank(issuer)) {
                            SAMLSSOServiceProviderDO serviceProviderDO =
                                    SAMLSSOUtil.getSPConfig(SAMLSSOUtil.getTenantDomainFromThreadLocal(),
                                    SAMLSSOUtil.splitAppendedTenantDomain(issuer));
                            if (serviceProviderDO != null) {
                                // For IDP init SLO, priority should be given to SLO response URL over default ACS.
                                acsUrl = serviceProviderDO.getSloResponseURL();
                                if (StringUtils.isBlank(acsUrl)) {
                                    acsUrl = serviceProviderDO.getDefaultAssertionConsumerUrl();
                                }

                                // Check whether ReturnToUrl query param is included in the configured Urls.
                                if (StringUtils.isNotBlank(returnToUrl)) {
                                    List<String> returnToUrls = serviceProviderDO.getIdpInitSLOReturnToURLList();
                                    if (returnToUrls.contains(returnToUrl)) {
                                        acsUrl += "&returnTo=" +
                                                URLEncoder.encode(returnToUrl, SAMLSSOConstants.ENCODING_FORMAT);
                                    }
                                }
                            }
                        }
                    }
                    sendNotification(errorResp, SAMLSSOConstants.Notification.INVALID_MESSAGE_STATUS,
                                     SAMLSSOConstants.Notification.EXCEPTION_MESSAGE,
                                     acsUrl, req, resp);
                }
            }
        }
    }

    /**
     * If the SAMLRequest is a Logout request then IDP will send logout requests to other session
     * participants and then sends the logout Response back to the initiator. In case of
     * authentication request, check if there is a valid session for the user, if there is, the user
     * will be redirected directly to the Service Provider, if not the user will be redirected to
     * the login page.
     *
     * @param req
     * @param resp
     * @param sessionId
     * @param samlRequest
     * @param relayState
     * @param authMode
     * @throws IdentityException
     * @throws IOException
     * @throws ServletException
     * @throws org.wso2.carbon.identity.base.IdentityException
     */
    private void handleSPInitSSO(HttpServletRequest req, HttpServletResponse resp,
                                 String queryString, String relayState, String authMode,
                                 String samlRequest, String sessionId, boolean isPost)
            throws UserStoreException, IdentityException, IOException, ServletException {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SAML_INBOUND_SERVICE, PROCESS_SAML_REQUEST);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(SAMLSSOConstants.LogConstants.InputKeys.QUERY_STRING, queryString);
        }
        String rpSessionId = req.getParameter(MultitenantConstants.SSO_AUTH_SESSION_ID);
        SAMLSSOService samlSSOService = new SAMLSSOService();

        SAMLSSOReqValidationResponseDTO signInRespDTO = samlSSOService.validateSPInitSSORequest(
                samlRequest, queryString, sessionId, rpSessionId, authMode, isPost, getLoggedInTenantDomain(req));

        setSPAttributeToRequest(req, signInRespDTO.getIssuer(), SAMLSSOUtil.getTenantDomainFromThreadLocal());

        if (!signInRespDTO.isLogOutReq()) { // an <AuthnRequest> received
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                diagnosticLogBuilder.resultMessage("Handling SP Initiated SSO request.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            if (signInRespDTO.isValid()) {
                sendToFrameworkForAuthentication(req, resp, signInRespDTO, relayState, isPost);
            } else {
                //TODO send invalid response to SP
                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.SAML_REQUEST)) {
                    log.debug("Invalid SAML SSO Request : " + samlRequest);
                }
                String errorResp = signInRespDTO.getResponse();
                sendNotification(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                        SAMLSSOConstants.Notification.EXCEPTION_MESSAGE,
                        signInRespDTO.getAssertionConsumerURL(), req, resp);
            }
        } else { // a <LogoutRequest> received
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                diagnosticLogBuilder.resultMessage("Handling SP Initiated SLO request.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
            if (signInRespDTO.isValid()) {
                sendToFrameworkForLogout(req, resp, signInRespDTO, relayState, sessionId, false, isPost);
            } else {
                if (log.isDebugEnabled() &&
                        IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.SAML_REQUEST)) {
                    log.debug("Invalid SAML SSO Logout Request : " + samlRequest);
                }
                if (signInRespDTO.isLogoutFromAuthFramework()) {
                    sendToFrameworkForLogout(req, resp, signInRespDTO, null, sessionId, true, isPost);
                } else {
                    //TODO send invalid response to SP
                    String errorResp = signInRespDTO.getResponse();
                    sendNotification(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                                     SAMLSSOConstants.Notification.EXCEPTION_MESSAGE,
                                     signInRespDTO.getAssertionConsumerURL(), req, resp);
                }
            }
        }
    }

    /**
     * Sends the user for authentication to the login page
     *
     * @param req
     * @param resp
     * @param signInRespDTO
     * @param relayState
     * @throws ServletException
     * @throws IOException
     */
    private void sendToFrameworkForAuthentication(HttpServletRequest req, HttpServletResponse resp,
                                                  SAMLSSOReqValidationResponseDTO signInRespDTO, String relayState, boolean isPost)
            throws ServletException, IOException, UserStoreException, IdentityException {

        SAMLSSOSessionDTO sessionDTO = new SAMLSSOSessionDTO();
        sessionDTO.setHttpQueryString(req.getQueryString());
        sessionDTO.setDestination(signInRespDTO.getDestination());
        sessionDTO.setRelayState(relayState);
        sessionDTO.setRequestMessageString(signInRespDTO.getRequestMessageString());
        sessionDTO.setIssuer(signInRespDTO.getIssuer());
        sessionDTO.setIssuerQualifier(signInRespDTO.getIssuerQualifier());
        sessionDTO.setRequestID(signInRespDTO.getId());
        sessionDTO.setSubject(signInRespDTO.getSubject());
        sessionDTO.setRelyingPartySessionId(signInRespDTO.getRpSessionId());
        sessionDTO.setAssertionConsumerURL(signInRespDTO.getAssertionConsumerURL());
        sessionDTO.setTenantDomain(SAMLSSOUtil.getTenantDomainFromThreadLocal());
        sessionDTO.setAttributeConsumingServiceIndex(signInRespDTO.getAttributeConsumingServiceIndex());
        sessionDTO.setForceAuth(signInRespDTO.isForceAuthn());
        sessionDTO.setPassiveAuth(signInRespDTO.isPassive());
        sessionDTO.setValidationRespDTO(signInRespDTO);
        sessionDTO.setIdPInitSSO(signInRespDTO.isIdPInitSSO());
        addRequestedAuthenticationContextClassReferences(sessionDTO, signInRespDTO);
        sessionDTO.setRequestedAttributes(signInRespDTO.getRequestedAttributes());
        sessionDTO.setRequestedAuthnContextComparison(signInRespDTO.getRequestedAuthnContextComparison());
        sessionDTO.setProperties(signInRespDTO.getProperties());
        sessionDTO.setLoggedInTenantDomain(getLoggedInTenantDomain(req));

        String sessionDataKey = UUID.randomUUID().toString();
        addSessionDataToCache(sessionDataKey, sessionDTO);

        String selfPath = ServiceURLBuilder.create().addPath(req.getContextPath()).build().getRelativeInternalURL();
        // Setting authentication request context
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();

        // Adding query parameters
        authenticationRequest.appendRequestQueryParams(req.getParameterMap());
        for (Enumeration headerNames = req.getHeaderNames(); headerNames.hasMoreElements(); ) {
            String headerName = headerNames.nextElement().toString();
            authenticationRequest.addHeader(headerName, req.getHeader(headerName));
        }

        authenticationRequest.setRelyingParty(signInRespDTO.getIssuer());
        authenticationRequest.setCommonAuthCallerPath(selfPath);
        authenticationRequest.setForceAuth(signInRespDTO.isForceAuthn());
        if (!authenticationRequest.getForceAuth() && authenticationRequest.getRequestQueryParam("forceAuth") != null) {
            String[] forceAuth = authenticationRequest.getRequestQueryParam("forceAuth");
            if (!forceAuth[0].trim().isEmpty() && Boolean.parseBoolean(forceAuth[0].trim())) {
                authenticationRequest.setForceAuth(Boolean.parseBoolean(forceAuth[0].trim()));
            }
        }
        authenticationRequest.setPassiveAuth(signInRespDTO.isPassive());
        authenticationRequest.setTenantDomain(sessionDTO.getTenantDomain());
        authenticationRequest.setPost(isPost);

        // Creating cache entry and adding entry to the cache before calling to commonauth
        AuthenticationRequestCacheEntry authRequest = new AuthenticationRequestCacheEntry
                (authenticationRequest);
        addAuthenticationRequestToRequest(req, authRequest);
        if (signInRespDTO.getAuthenticationContextClassRefList() != null) {
            List<String> acrList = signInRespDTO.getAuthenticationContextClassRefList().stream()
                    .map(acr -> acr.getAuthenticationContextClassReference()).collect(Collectors.toList());
            req.setAttribute(ACR_VALUES_ATTRIBUTE, acrList);
        }
        //Add user atributes
        req.setAttribute(SAMLSSOConstants.REQUESTED_ATTRIBUTES, signInRespDTO.getRequestedAttributes());
        sendRequestToFramework(req, resp, sessionDataKey, FrameworkConstants.RequestType.CLAIM_TYPE_SAML_SSO);
    }

    private void addRequestedAuthenticationContextClassReferences(SAMLSSOSessionDTO sessionDTO,
                                                                  SAMLSSOReqValidationResponseDTO signInRespDTO) {

        if (signInRespDTO.getAuthenticationContextClassRefList() != null) {
            signInRespDTO.getAuthenticationContextClassRefList().forEach(
                    a -> sessionDTO.addAuthenticationContextClassRef(a));
        }
    }

    private void addAuthenticationRequestToRequest(HttpServletRequest request,AuthenticationRequestCacheEntry authRequest){
        request.setAttribute(FrameworkConstants.RequestAttribute.AUTH_REQUEST, authRequest);
    }

    private void sendToFrameworkForLogout(HttpServletRequest request, HttpServletResponse response,
                                          SAMLSSOReqValidationResponseDTO signInRespDTO, String relayState,
                                          String sessionId,
                                          boolean invalid, boolean isPost) throws ServletException, IOException,
            URLBuilderException {

        SAMLSSOSessionDTO sessionDTO = new SAMLSSOSessionDTO();
        sessionDTO.setHttpQueryString(request.getQueryString());
        sessionDTO.setRelayState(relayState);
        sessionDTO.setSessionId(sessionId);
        sessionDTO.setLogoutReq(true);
        sessionDTO.setInvalidLogout(invalid);
        sessionDTO.setLoggedInTenantDomain(getLoggedInTenantDomain(request));

        Properties properties = new Properties();
        properties.put(SAMLSSOConstants.IS_POST, isPost);
        sessionDTO.setProperties(properties);

        if (signInRespDTO != null) {
            sessionDTO.setDestination(signInRespDTO.getDestination());
            sessionDTO.setRequestMessageString(signInRespDTO.getRequestMessageString());
            sessionDTO.setIssuer(signInRespDTO.getIssuer());
            sessionDTO.setRequestID(signInRespDTO.getId());
            sessionDTO.setSubject(signInRespDTO.getSubject());
            sessionDTO.setRelyingPartySessionId(signInRespDTO.getRpSessionId());
            sessionDTO.setAssertionConsumerURL(signInRespDTO.getAssertionConsumerURL());
            sessionDTO.setValidationRespDTO(signInRespDTO);
        }

        String sessionDataKey = UUID.randomUUID().toString();
        addSessionDataToCache(sessionDataKey, sessionDTO);

        String selfPath = ServiceURLBuilder.create().addPath(request.getContextPath()).build().getRelativeInternalURL();

        //Add all parameters to authentication context before sending to authentication
        // framework
        AuthenticationRequest authenticationRequest = new
                AuthenticationRequest();
        authenticationRequest.addRequestQueryParam(FrameworkConstants.RequestParams.LOGOUT,
                                                   new String[]{"true"});
        authenticationRequest.setRequestQueryParams(request.getParameterMap());
        authenticationRequest.setCommonAuthCallerPath(selfPath);
        authenticationRequest.setPost(isPost);
        authenticationRequest.setTenantDomain(SAMLSSOUtil.getTenantDomainFromThreadLocal());

        if (signInRespDTO != null) {
            authenticationRequest.setRelyingParty(signInRespDTO.getIssuer());
        }
        authenticationRequest.appendRequestQueryParams(request.getParameterMap());
        //Add headers to AuthenticationRequestContext
        for (Enumeration e = request.getHeaderNames(); e.hasMoreElements(); ) {
            String headerName = e.nextElement().toString();
            authenticationRequest.addHeader(headerName, request.getHeader(headerName));
        }

        AuthenticationRequestCacheEntry authRequest = new AuthenticationRequestCacheEntry
                (authenticationRequest);
        addAuthenticationRequestToRequest(request, authRequest);
        removeTokenIdCookie(request, response, sessionDTO.getLoggedInTenantDomain());
        sendRequestToFramework(request, response, sessionDataKey, FrameworkConstants.RequestType.CLAIM_TYPE_SAML_SSO);
    }

    /**
     * Send the Artifact as a response to a SAML authentication request.
     *
     * @param resp                 Response object to be sent.
     * @param relayState           Relay state of the request.
     * @param artifact             Generated SAML2 artifact.
     * @param assertionConsumerUrl ACU to be sent.
     * @throws IOException
     */
    private void sendArtifact(HttpServletResponse resp, String relayState, String artifact,
                              String assertionConsumerUrl) throws IOException {

        // Set the HTTP Headers: HTTP proxies and user agents should not cache the artifact
        resp.addHeader(SAMLSSOConstants.PRAGMA_PARAM_KEY, SAMLSSOConstants.CACHE_CONTROL_VALUE_NO_CACHE);
        resp.addHeader(SAMLSSOConstants.CACHE_CONTROL_PARAM_KEY, SAMLSSOConstants.CACHE_CONTROL_VALUE_NO_CACHE);

        Map<String, String> queryParams = new HashMap<>();

        String encodedArtifact = URLEncoder.encode(artifact, StandardCharsets.UTF_8.name());
        queryParams.put(SAMLSSOConstants.SAML_ART, encodedArtifact);

        if (relayState != null) {
            String encodedRelayState = URLEncoder.encode(relayState, StandardCharsets.UTF_8.name());
            queryParams.put(SAMLSSOConstants.RELAY_STATE, encodedRelayState);
        }

        resp.sendRedirect(FrameworkUtils.appendQueryParamsToUrl(assertionConsumerUrl, queryParams));
    }

    /**
     * Sends the Response message back to the Service Provider.
     *
     * @param req
     * @param resp
     * @param relayState
     * @param response
     * @param acUrl
     * @param subject
     * @throws ServletException
     * @throws IOException
     */
    private void sendResponse(HttpServletRequest req, HttpServletResponse resp, String relayState,
                              String response, String acUrl, String subject, String authenticatedIdPs,
                              String tenantDomain)
            throws ServletException, IOException, IdentityException {

        String spName = resolveAppName();
        acUrl = getACSUrlWithTenantPartitioning(acUrl, tenantDomain);

        if (acUrl == null || acUrl.trim().length() == 0) {
            // if ACS is null. Send to error page
            log.error("ACS Url is Null");
            throw IdentityException.error("Unexpected error in sending message out");
        }

        if (response == null || response.trim().length() == 0) {
            // if response is null
            log.error("Response message is Null");
            throw IdentityException.error("Unexpected error in sending message out");
        }

        resp.setContentType("text/html; charset=UTF-8");
        if (isSAMLECPRequest(req)) {
            generateResponseForECPRequest(resp, response, acUrl);
        } else if (IdentitySAMLSSOServiceComponent.isSAMLSSOResponseJspPageAvailable()) {
            generateSamlPostPageFromJSP(req, resp, acUrl, response, relayState, authenticatedIdPs,
                    SAMLSSOConstants.SAML_RESP, spName);
        } else if (IdentitySAMLSSOServiceComponent.isSAMLSSOResponseHtmlPageAvailable()) {
            generateSamlPostPage(IdentitySAMLSSOServiceComponent.getSsoRedirectHtml(), resp, acUrl, response,
                    relayState, authenticatedIdPs, SAMLSSOConstants.SAML_RESP, spName);
        } else {
            generateSamlPostPage(formPostPageTemplate, resp, acUrl, response, relayState, authenticatedIdPs,
                    SAMLSSOConstants.SAML_RESP, spName);
        }
    }

    private void generateSamlPostPage(String formPostPage, HttpServletResponse resp, String acUrl, String samlMessage,
                                      String relayState, String authenticatedIdPs, String samlMessageType,
                                      String spName) throws IOException {

        String pageWithAcs = formPostPage.replace("$acUrl", acUrl);
        String pageWithApp = pageWithAcs.replace("$app", acUrl);

        if (StringUtils.isNotBlank(spName)) {
            pageWithApp = pageWithAcs.replace("$app", spName);
        }

        String pageWithAcsResponse = pageWithApp.replace("<!--$params-->",
                buildPostPageInputs(samlMessageType, samlMessage));
        String pageWithAcsResponseRelay = pageWithAcsResponse;

        if (relayState != null) {
            pageWithAcsResponseRelay = pageWithAcsResponse.replace("<!--$params-->",
                    buildPostPageInputs(SAMLSSOConstants.RELAY_STATE, relayState));
        }

        String finalPage = pageWithAcsResponseRelay;
        if (authenticatedIdPs != null && !authenticatedIdPs.isEmpty()) {
            finalPage = pageWithAcsResponseRelay.replace(
                    "<!--$additionalParams-->",
                    "<input type='hidden' name='AuthenticatedIdPs' value='"
                            + Encode.forHtmlAttribute(authenticatedIdPs) + "'/>");
        }

        PrintWriter out = resp.getWriter();
        out.print(finalPage);

        if (log.isDebugEnabled()) {
            log.debug("samlsso_response.html " + finalPage);
        }
    }

    private void generateSamlPostPage(String formPostPage, HttpServletResponse resp, String acUrl, String samlMessage,
                                      String samlMessageType, String spName) throws IOException {

        generateSamlPostPage(formPostPage, resp, acUrl, samlMessage, null, null, samlMessageType, spName);
    }

    private void generateSamlPostPageFromJSP(HttpServletRequest req, HttpServletResponse resp, String acUrl,
                                             String samlMessage, String relayState, String authenticatedIdPs,
                                             String samlMessageType, String spName)
            throws ServletException, IOException {

        req.setAttribute(SAMLSSOConstants.ATTR_NAME_AC_URL, acUrl);
        req.setAttribute(SAMLSSOConstants.ATTR_NAME_SP_NAME, spName);
        req.setAttribute(SAMLSSOConstants.ATTR_NAME_SAML_MESSAGE_TYPE, samlMessageType);
        req.setAttribute(SAMLSSOConstants.ATTR_NAME_SAML_MESSAGE, samlMessage);
        req.setAttribute(SAMLSSOConstants.ATTR_NAME_RELAY_STATE, relayState);
        req.setAttribute(SAMLSSOConstants.ATTR_NAME_AUTHENTICATED_IDPS, authenticatedIdPs);
        ServletContext authEndpoint = getServletContext().getContext("/authenticationendpoint");
        RequestDispatcher requestDispatcher = authEndpoint.getRequestDispatcher("/samlsso_response.jsp");
        requestDispatcher.include(req, resp);
    }

    private void generateSamlPostPageFromJSP(HttpServletRequest req, HttpServletResponse resp, String acUrl,
                                             String samlMessage, String samlMessageType, String spName)
            throws ServletException, IOException {

        generateSamlPostPageFromJSP(req, resp, acUrl, samlMessage, null, null, samlMessageType, spName);
    }

    /**
     * This method handles authentication and sends authentication Response message back to the
     * Service Provider after successful authentication. In case of authentication failure the user
     * is prompted back for authentication.
     *
     * @param req
     * @param resp
     * @param sessionId
     * @throws IdentityException
     * @throws IOException
     * @throws ServletException
     */
    private void handleAuthenticationReponseFromFramework(HttpServletRequest req, HttpServletResponse resp,
                                                          String sessionId, SAMLSSOSessionDTO sessionDTO)
            throws UserStoreException, IdentityException, IOException, ServletException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SAML_INBOUND_SERVICE, "receive-authn-response");
            diagnosticLogBuilder.resultMessage("Received authentication response from framework")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                    .inputParam(SAMLSSOConstants.LogConstants.InputKeys.ISSUER, sessionDTO.getIssuer())
                    .inputParam(SAMLSSOConstants.LogConstants.InputKeys.CONSUMER_URL,
                            sessionDTO.getAssertionConsumerURL())
                    .inputParam(LogConstants.InputKeys.USER, LoggerUtils.isLogMaskingEnable ?
                            LoggerUtils.getMaskedContent(sessionDTO.getSubject()) : sessionDTO.getSubject());
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        String sessionDataKey = getSessionDataKey(req);
        AuthenticationResult authResult = getAuthenticationResult(req, sessionDataKey);

        SAMLSSOAuthnReqDTO authnReqDTO = new SAMLSSOAuthnReqDTO();
        populateAuthnReqDTOWithCachedSessionEntry(authnReqDTO, sessionDTO);
        populateAuthenticationContextClassRefResult(authResult, sessionDTO, authnReqDTO);

        String tenantDomain = authnReqDTO.getTenantDomain();
        String issuer = authnReqDTO.getIssuer();
        String authenticationRequestId = authnReqDTO.getId();
        String assertionConsumerURL = authnReqDTO.getAssertionConsumerURL();
        authnReqDTO.setSamlECPEnabled(Boolean.valueOf(req.getParameter(SAMLECPConstants.IS_ECP_REQUEST)));

        //get sp configs
        SAMLSSOServiceProviderDO serviceProviderConfigs = getServiceProviderConfig(authnReqDTO);

        if (serviceProviderConfigs != null) {
            populateAuthnReqDTOWithRequiredServiceProviderConfigs(authnReqDTO, serviceProviderConfigs);
            if (assertionConsumerURL == null) {
                assertionConsumerURL = authnReqDTO.getAssertionConsumerURL();
            }
        }

        if (authResult == null || !authResult.isAuthenticated()) {

            if (log.isDebugEnabled()) {
                if (authResult == null) {
                    log.debug("Authentication result data not found for key : " + sessionDataKey);
                } else {
                    log.debug("User authentication has failed.");
                }
            }

            if (sessionDTO.getValidationRespDTO().isPassive()) { //if passive
                List<String> statusCodes = new ArrayList<>();
                statusCodes.add(SAMLSSOConstants.StatusCodes.NO_PASSIVE);
                statusCodes.add(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR);
                String errorResp = SAMLSSOUtil.buildErrorResponse(authenticationRequestId, statusCodes, "Cannot " +
                        "authenticate Subject in Passive Mode", assertionConsumerURL);

                sendResponse(req, resp, sessionDTO.getRelayState(), errorResp, assertionConsumerURL, sessionDTO
                        .getValidationRespDTO().getSubject(), null, sessionDTO.getTenantDomain());
                return;
            } else { // if forceAuthn or normal flow
                if (authResult != null && !authResult.isAuthenticated()) {

                    List<String> statusCodes = new ArrayList<String>();
                    statusCodes.add(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE);
                    statusCodes.add(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR);

                    String errorResp = SAMLSSOUtil.buildCompressedErrorResponse(authenticationRequestId, statusCodes,
                            "User authentication failed", assertionConsumerURL);
                    sendNotification(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS, SAMLSSOConstants
                            .Notification.EXCEPTION_MESSAGE, assertionConsumerURL, req, resp);
                    return;
                } else {
                    throw IdentityException.error(IdentityException.class, "Could not find " + "session state " +
                            "information for issuer : " + issuer + " in tenant domain : " + tenantDomain + " for " +
                            "session identifier : " + sessionDataKey);
                }
            }
        } else {
            populateAuthnReqDTOWithAuthenticationResult(authnReqDTO, authResult);
            req.setAttribute(SAMLSSOConstants.AUTHENTICATION_RESULT, authResult);

            String relayState = null;
            if (req.getParameter(SAMLSSOConstants.RELAY_STATE) != null) {
                relayState = req.getParameter(SAMLSSOConstants.RELAY_STATE);
            } else {
                relayState = sessionDTO.getRelayState();
            }

            startTenantFlow(authnReqDTO.getTenantDomain());

            if (sessionId == null) {
                sessionId = getSamlSSOTokenIdFromSessionContext(authResult, authnReqDTO.getLoggedInTenantDomain());
            }

            SAMLSSOService samlSSOService = new SAMLSSOService();
            SAMLSSORespDTO authRespDTO = samlSSOService.authenticate(authnReqDTO, sessionId, authResult.isAuthenticated(),
                    authResult.getAuthenticatedAuthenticators(), SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD);

            if (authRespDTO.isSessionEstablished()) { // authenticated
                String sessionIdentifier =
                        (String) authResult.getProperty(FrameworkConstants.AnalyticsAttributes.SESSION_ID);
                storeTokenIdCookie(sessionId, req, resp, authnReqDTO.getTenantDomain(),
                        sessionDTO.getLoggedInTenantDomain(), sessionIdentifier);
                removeSessionDataFromCache(req.getParameter(SAMLSSOConstants.SESSION_DATA_KEY));

                if (authnReqDTO.isSAML2ArtifactBindingEnabled()) {
                    sendArtifact(resp, relayState, authRespDTO.getRespString(), authRespDTO.getAssertionConsumerURL());
                } else {
                    sendResponse(req, resp, relayState, authRespDTO.getRespString(),
                            authRespDTO.getAssertionConsumerURL(),
                            authRespDTO.getSubject().getAuthenticatedSubjectIdentifier(),
                            authResult.getAuthenticatedIdPs(), sessionDTO.getTenantDomain());
                }
            } else { // authentication FAILURE
                String errorResp = authRespDTO.getRespString();
                sendNotification(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                        SAMLSSOConstants.Notification.EXCEPTION_MESSAGE,
                        authRespDTO.getAssertionConsumerURL(), req, resp);
            }
        }
    }

    /**
     * Get samlssoTokenId from session context.
     *
     * @param authenticationResult Authentication Result.
     * @param loginTenantDomain    Login Tenant Domain.
     */
    private String getSamlSSOTokenIdFromSessionContext(AuthenticationResult authenticationResult,
                                                       String loginTenantDomain) {

        String sessionIdentifier =
                (String) authenticationResult.getProperty(FrameworkConstants.AnalyticsAttributes.SESSION_ID);
        if (StringUtils.isNotBlank(sessionIdentifier)) {
            SessionContext sessionContext = getSessionContext(sessionIdentifier, loginTenantDomain);
            if (sessionContext != null) {
                if (authenticationResult.getSubject() != null) {
                    Object samlssoTokenId = sessionContext.getProperty(SAMLSSOConstants.SAML_SSO_TOKEN_ID_COOKIE);
                    if (samlssoTokenId != null) {
                        return (String) samlssoTokenId;
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Authenticated user attribute is not found in authentication result");
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Session context is not found for the session identifier: " + sessionIdentifier);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Session context identifier is not found in the authentication result.");
            }
        }
        return UUID.randomUUID().toString();
    }

    private void handleLogoutResponseFromFramework(HttpServletRequest request, HttpServletResponse response,
                                                   SAMLSSOSessionDTO sessionDTO)
            throws ServletException, IOException, IdentityException {

        SAMLSSOReqValidationResponseDTO validationResponseDTO = sessionDTO.getValidationRespDTO();

        if (validationResponseDTO != null) {
            removeSessionDataFromCache(request.getParameter(SAMLSSOConstants.SESSION_DATA_KEY));
            String sessionIndex = validationResponseDTO.getSessionIndex();
            List<SAMLSSOServiceProviderDO> samlssoServiceProviderDOList =
                    SAMLSSOUtil.getRemainingSessionParticipantsForSLO(sessionIndex, sessionDTO.getIssuer(),
                            validationResponseDTO.isIdPInitSLO(), sessionDTO.getLoggedInTenantDomain());

            // Get the SP list and check for other session participants that have enabled single logout.
            if (samlssoServiceProviderDOList.isEmpty()) {
                respondToOriginalIssuer(request, response, sessionDTO);
            } else {
                String originalIssuerLogoutRequestId = null;
                if (!validationResponseDTO.isIdPInitSLO()) {
                    originalIssuerLogoutRequestId = validationResponseDTO.getId();
                }
                sendLogoutRequestToSessionParticipant(request, response, samlssoServiceProviderDOList,
                        originalIssuerLogoutRequestId, validationResponseDTO.isIdPInitSLO(), sessionDTO.getRelayState(),
                        validationResponseDTO.getReturnToURL(), sessionIndex, sessionDTO.getIssuer(),
                        sessionDTO.getLoggedInTenantDomain());
            }
        } else {
            sendErrorResponseToOriginalIssuer(request, response, sessionDTO);
        }
    }
    /**
     * Reads the ACR from the framework and associate it to the ACR to be returned.
     *
     * @param authenticationResult  Authentication result object
     * @param sessionDTO  the SAML Session DTO
     * @param authnReqDTO the SAML Request DTO
     */
    private void populateAuthenticationContextClassRefResult(AuthenticationResult authenticationResult,
                                                             SAMLSSOSessionDTO sessionDTO,
                                                             SAMLSSOAuthnReqDTO authnReqDTO) {

        SessionAuthHistory sessionAuthHistory = null;
        if (authenticationResult != null) {
            sessionAuthHistory = (SessionAuthHistory) authenticationResult.getProperty(
                    FrameworkConstants.SESSION_AUTH_HISTORY);
        }

        if (sessionAuthHistory != null && sessionAuthHistory.getSelectedAcrValue() != null) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Found the selected ACR value from the framework as : " +
                                sessionAuthHistory.getSelectedAcrValue() +
                                " , Hence creating the AuthenticationContextProperty");
            }
            List<AuthenticationContextProperty> authenticationContextProperties = authnReqDTO
                    .getIdpAuthenticationContextProperties().get(SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF);
            List<String> acrListFromFramework = new ArrayList<>();
            acrListFromFramework.add(sessionAuthHistory.getSelectedAcrValue());
            if (authenticationContextProperties == null) {
                authenticationContextProperties = new ArrayList<>();
                authnReqDTO.getIdpAuthenticationContextProperties().put(SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF,
                        authenticationContextProperties);
            }
            Map<String, Object> passThroughData = new HashMap<>();
            AuthenticationContextProperty acrFromFramework = new AuthenticationContextProperty(
                    IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID,
                    IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID,
                    passThroughData);
            passThroughData.put(SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF, acrListFromFramework);
            passThroughData.put(SAMLSSOConstants.AUTHN_INSTANT, sessionAuthHistory.getSessionCreatedTime());
            if (log.isDebugEnabled()) {
                log.debug(
                        "Setting the AuthnInst as session create time : " + sessionAuthHistory.getSessionCreatedTime());
            }

            authenticationContextProperties.add(acrFromFramework);
        }
    }

    private void sendLogoutRequestToSessionParticipant(HttpServletRequest request, HttpServletResponse response,
                                                       List<SAMLSSOServiceProviderDO> samlssoServiceProviderDOList,
                                                       String originalIssuerLogoutRequestId, boolean isIdPInitSLO,
                                                       String relayState, String returnToURL, String sessionIndex,
                                                       String originalLogoutRequestIssuer, String loginTenantDomain)
            throws IOException, IdentityException, ServletException {

        for (SAMLSSOServiceProviderDO entry : samlssoServiceProviderDOList) {
            if (entry.isDoFrontChannelLogout()) {
                doFrontChannelSLO(request, response, entry, sessionIndex, originalLogoutRequestIssuer,
                        originalIssuerLogoutRequestId, isIdPInitSLO, relayState, returnToURL, loginTenantDomain);
                break;
            }
        }
    }

    private void respondToOriginalIssuer(HttpServletRequest request, HttpServletResponse response,
                                         SAMLSSOSessionDTO sessionDTO) throws ServletException, IOException,
            IdentityException {

        SAMLSSOReqValidationResponseDTO validationResponseDTO = sessionDTO.getValidationRespDTO();

        if (SSOSessionPersistenceManager.getSessionIndexFromCache(sessionDTO.getSessionId(),
                sessionDTO.getLoggedInTenantDomain()) == null) {
            // Remove tokenId Cookie when there is no session available.
            removeTokenIdCookie(request, response, sessionDTO.getLoggedInTenantDomain());
        }

        if (validationResponseDTO.isIdPInitSLO()) {
            // Redirecting to the return URL or IS logout page.
            response.sendRedirect(validationResponseDTO.getReturnToURL());
        } else {
            // Sending LogoutResponse back to the initiator.
            sendResponse(request, response, sessionDTO.getRelayState(), validationResponseDTO.getLogoutResponse(),
                    validationResponseDTO.getAssertionConsumerURL(), validationResponseDTO.getSubject(),
                    null, sessionDTO.getTenantDomain());
        }
    }

    /**
     * Send an error response to original issuer when the SAML request validation is invalid.
     *
     * @param request    HttpServlet Request.
     * @param response   HttpServlet Response.
     * @param sessionDTO SAMLSSOSessionDTO.
     * @throws IOException       If error response building fails.
     * @throws IdentityException If error response building fails.
     * @throws ServletException  If sending error response fails.
     */
    private void sendErrorResponseToOriginalIssuer(HttpServletRequest request, HttpServletResponse response,
                                                   SAMLSSOSessionDTO sessionDTO)
            throws IOException, IdentityException, ServletException {

        String acsUrl = sessionDTO.getAssertionConsumerURL();
        if (StringUtils.isBlank(acsUrl) && sessionDTO.getIssuer() != null) {
            SAMLSSOServiceProviderDO serviceProviderDO =
                    SAMLSSOUtil.getSPConfig(SAMLSSOUtil.getTenantDomainFromThreadLocal(), sessionDTO.getIssuer());
            if (serviceProviderDO != null) {
                acsUrl = serviceProviderDO.getSloResponseURL();
                if (StringUtils.isBlank(acsUrl)) {
                    acsUrl = serviceProviderDO.getDefaultAssertionConsumerUrl();
                }
            }
        }
        String errorResp = SAMLSSOUtil.buildErrorResponse(
                SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                "Invalid request",
                acsUrl);
        sendNotification(errorResp, SAMLSSOConstants.Notification.INVALID_MESSAGE_STATUS,
                SAMLSSOConstants.Notification.INVALID_MESSAGE_MESSAGE,
                acsUrl, request, response);
    }

    private Cookie getTokenIdCookie(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (StringUtils.equals(cookie.getName(), "samlssoTokenId")) {
                    return cookie;
                }
            }
        }
        return null;
    }

    /**
     * @param sessionId            Session Id.
     * @param req                  HttpServlet Request.
     * @param resp                 HttpServlet Response.
     * @param tenantDomain         Tenant Domain
     * @param loggedInTenantDomain Logged In Tenant Domain.
     * @param sessionIdentifier    Session Identifier
     */
    private void storeTokenIdCookie(String sessionId, HttpServletRequest req, HttpServletResponse resp,
                                    String tenantDomain, String loggedInTenantDomain, String sessionIdentifier) {

        ServletCookie samlssoTokenIdCookie = new ServletCookie(SAML_SSO_TOKEN_ID_COOKIE, sessionId);
        IdentityCookieConfig samlssoTokenIdCookieConfig = IdentityUtil
                .getIdentityCookieConfig(SAML_SSO_TOKEN_ID_COOKIE);

        // Get age of the samlssoTokenId cookie.
        SessionContext sessionContext = getSessionContext(sessionIdentifier, loggedInTenantDomain);
        Integer cookieAge = null;
        if (sessionContext != null && sessionContext.isRememberMe()) {
            cookieAge = IdPManagementUtil.getRememberMeTimeout(loggedInTenantDomain);
        }

        samlssoTokenIdCookie.setSecure(true);
        samlssoTokenIdCookie.setHttpOnly(true);

        boolean isTenantQualifiedCookie = false;
        if (IdentityTenantUtil.isTenantedSessionsEnabled() &&
                sessionId.endsWith(SAMLSSOConstants.TENANT_QUALIFIED_TOKEN_ID_COOKIE_SUFFIX)) {
            if (loggedInTenantDomain != null) {
                samlssoTokenIdCookie.setPath(FrameworkConstants.TENANT_CONTEXT_PREFIX + loggedInTenantDomain +
                        SAMLSSOConstants.COOKIE_ROOT_PATH);
            } else {
                samlssoTokenIdCookie.setPath(FrameworkConstants.TENANT_CONTEXT_PREFIX + tenantDomain +
                        SAMLSSOConstants.COOKIE_ROOT_PATH);
            }
            isTenantQualifiedCookie = true;
        } else {
            samlssoTokenIdCookie.setPath(SAMLSSOConstants.COOKIE_ROOT_PATH);
        }

        samlssoTokenIdCookie.setSameSite(SameSiteCookie.NONE);
        if (cookieAge != null) {
            samlssoTokenIdCookie.setMaxAge(cookieAge);
        }
        if (samlssoTokenIdCookieConfig != null) {
            updateSAMLSSOIdCookieConfig(samlssoTokenIdCookie, samlssoTokenIdCookieConfig, cookieAge,
                    isTenantQualifiedCookie);
        }
        resp.addCookie(samlssoTokenIdCookie);
    }

    /**
     * @deprecated This method was deprecated to enable tenanted paths for Saml Sso Token Id Cookie.
     * Use {@link #removeTokenIdCookie(HttpServletRequest, HttpServletResponse, String)} instead.
     */
    @Deprecated
    public void removeTokenIdCookie(HttpServletRequest req, HttpServletResponse resp) {

        removeTokenIdCookie(req, resp, SAMLSSOUtil.getTenantDomainFromThreadLocal());
    }

    /**
     * Remove Saml SSO Token Id Cookie.
     *
     * @param req                  HttpServlet Request.
     * @param resp                 HttpServlet Response.
     * @param loggedInTenantDomain Logged in Tenant Domain.
     */
    public void removeTokenIdCookie(HttpServletRequest req, HttpServletResponse resp, String loggedInTenantDomain) {

        Cookie[] cookies = req.getCookies();
        IdentityCookieConfig samlssoTokenIdCookieConfig = IdentityUtil
                .getIdentityCookieConfig(SAML_SSO_TOKEN_ID_COOKIE);
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (StringUtils.equals(cookie.getName(), "samlssoTokenId")) {
                    ServletCookie samlSsoTokenIdCookie = new ServletCookie(SAML_SSO_TOKEN_ID_COOKIE, cookie.getValue());
                    if (log.isDebugEnabled()) {
                        log.debug("SSO tokenId Cookie is removed");
                    }
                    samlSsoTokenIdCookie.setHttpOnly(true);
                    samlSsoTokenIdCookie.setSecure(true);

                    boolean isTenantQualifiedCookie = false;
                    if (IdentityTenantUtil.isTenantedSessionsEnabled() && cookie.getValue() != null &&
                            cookie.getValue().endsWith(SAMLSSOConstants.TENANT_QUALIFIED_TOKEN_ID_COOKIE_SUFFIX)) {
                        samlSsoTokenIdCookie.setPath(FrameworkConstants.TENANT_CONTEXT_PREFIX + loggedInTenantDomain +
                                SAMLSSOConstants.COOKIE_ROOT_PATH);
                        isTenantQualifiedCookie = true;
                    } else {
                        samlSsoTokenIdCookie.setPath(SAMLSSOConstants.COOKIE_ROOT_PATH);
                    }
                    samlSsoTokenIdCookie.setSameSite(SameSiteCookie.NONE);

                    if (samlssoTokenIdCookieConfig != null) {
                        updateSAMLSSOIdCookieConfig(samlSsoTokenIdCookie, samlssoTokenIdCookieConfig, 0,
                                isTenantQualifiedCookie);
                    }
                    samlSsoTokenIdCookie.setMaxAge(0);
                    resp.addCookie(samlSsoTokenIdCookie);
                    break;
                }
            }
        }
    }

    private String getACSUrlWithTenantPartitioning(String acsUrl, String tenantDomain) {
        String acsUrlWithTenantDomain = acsUrl;
        if (tenantDomain != null && "true".equals(IdentityUtil.getProperty(
                IdentityConstants.ServerConfig.SSO_TENANT_PARTITIONING_ENABLED))) {
            acsUrlWithTenantDomain =
                    acsUrlWithTenantDomain + "?" +
                            MultitenantConstants.TENANT_DOMAIN + "=" + tenantDomain;
        }
        return acsUrlWithTenantDomain;
    }

    private void addSessionDataToCache(String sessionDataKey, SAMLSSOSessionDTO sessionDTO) {
        SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionDataKey);
        SessionDataCacheEntry cacheEntry = new SessionDataCacheEntry();
        cacheEntry.setSessionDTO(sessionDTO);
        SessionDataCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    private SAMLSSOSessionDTO getSessionDataFromCache(String sessionDataKey) {
        SAMLSSOSessionDTO sessionDTO = null;
        SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionDataKey);
        SessionDataCacheEntry cacheEntry = SessionDataCache.getInstance().getValueFromCache(cacheKey);

        if (cacheEntry != null) {
            sessionDTO = cacheEntry.getSessionDTO();
        }

        return sessionDTO;
    }

    private void removeSessionDataFromCache(String sessionDataKey) {
        if (sessionDataKey != null) {
            SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionDataKey);
            SessionDataCache.getInstance().clearCacheEntry(cacheKey);
        }
    }

    /**
     * Get authentication result
     * When using federated or multiple steps authenticators, there is a redirection from commonauth to samlsso,
     * So in that case we cannot use request attribute and have to get the result from cache
     *
     * @param req Http servlet request
     * @param sessionDataKey Session data key
     * @return
     */
    private AuthenticationResult getAuthenticationResult(HttpServletRequest req, String sessionDataKey) {

        AuthenticationResult result = getAuthenticationResultFromRequest(req);
        if (result == null) {
            result = getAuthenticationResultFromCache(sessionDataKey);
        }
        return result;
    }

    private AuthenticationResult getAuthenticationResultFromCache(String sessionDataKey) {
        AuthenticationResult authResult = null;
        AuthenticationResultCacheEntry authResultCacheEntry = FrameworkUtils
                .getAuthenticationResultFromCache(sessionDataKey);
        if (authResultCacheEntry != null) {
            authResult = authResultCacheEntry.getResult();
        } else {
            log.error("Cannot find AuthenticationResult from the cache");
        }
        return authResult;
    }

    /**
     * Get authentication result attribute from request
     * @param req Http servlet request
     * @return Authentication result
     */
    private AuthenticationResult getAuthenticationResultFromRequest(HttpServletRequest req) {

        return (AuthenticationResult) req.getAttribute(FrameworkConstants.RequestAttribute.AUTH_RESULT);
    }

    /**
     * Remove authentication result from request
     * @param req
     */
    private void removeAuthenticationResult(HttpServletRequest req, String sessionDataKey) {

            FrameworkUtils.removeAuthenticationResultFromCache(sessionDataKey);
            req.removeAttribute(FrameworkConstants.RequestAttribute.AUTH_RESULT);
    }

    /**
     * Remove authentication result from request and cache
     * @param req
     */
    private void removeAuthenticationResultFromRequest(HttpServletRequest req) {

        req.removeAttribute(FrameworkConstants.RequestAttribute.AUTH_RESULT);
    }

    private void startTenantFlow(String tenantDomain) throws IdentityException {

        int tenantId = MultitenantConstants.SUPER_TENANT_ID;

        if (tenantDomain != null && !tenantDomain.trim().isEmpty() && !"null".equalsIgnoreCase(tenantDomain.trim())) {
            try {
                tenantId = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
                if (tenantId == -1) {
                    // invalid tenantId, hence throw exception to avoid setting invalid tenant info
                    // to CC
                    String message = "Invalid Tenant Domain : " + tenantDomain;
                    if (log.isDebugEnabled()) {
                        log.debug(message);
                    }
                    throw IdentityException.error(message);
                }
            } catch (UserStoreException e) {
                String message = "Error occurred while getting tenant ID from tenantDomain " + tenantDomain;
                log.error(message, e);
                throw IdentityException.error(message, e);
            }
        } else {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext
                .getThreadLocalCarbonContext();
        carbonContext.setTenantId(tenantId);
        carbonContext.setTenantDomain(tenantDomain);
    }

    private QueryParamDTO[] getQueryParams(HttpServletRequest request) {

        List<QueryParamDTO> queryParamDTOs =  new ArrayList<>();
        for(SAMLSSOConstants.QueryParameter queryParameter : SAMLSSOConstants.QueryParameter.values()) {
            queryParamDTOs.add(new QueryParamDTO(queryParameter.toString(),
                    request.getParameter(queryParameter.toString())));
        }

        return queryParamDTOs.toArray(new QueryParamDTO[queryParamDTOs.size()]);
    }

    /**
     * In SAML there is no redirection from authentication endpoint to  commonauth and it send a post request to samlsso
     * servlet and sending the request to authentication framework from here, this overload method not sending
     * sessionDataKey and type to commonauth that's why overloaded the method here
     *
     * @param request Http servlet request
     * @param response Http servlet response
     * @throws ServletException
     * @throws IOException
     */
    private void sendRequestToFramework(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SAML_INBOUND_SERVICE, HAND_OVER_TO_FRAMEWORK);
            diagnosticLogBuilder.resultMessage("Forward SAML request to framework for user authentication.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();

        CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(response);
        commonAuthenticationHandler.doGet(request, responseWrapper);

        Object object = request.getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);
        if (object != null) {
            AuthenticatorFlowStatus status = (AuthenticatorFlowStatus) object;
            if (status == AuthenticatorFlowStatus.INCOMPLETE) {
                if (responseWrapper.isRedirect()) {
                    response.sendRedirect(responseWrapper.getRedirectURL());
                } else {
                    if (responseWrapper.getContent().length > 0) {
                        responseWrapper.write();
                    }
                }
            } else {
                doGet(request, response);
            }
        } else {
            request.setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.UNKNOWN);
            doGet(request, response);
        }
    }

    /**
     * This method use to call authentication framework directly via API other than using HTTP redirects.
     * Sending wrapper request object to doGet method since other original request doesn't exist required parameters
     * Doesn't check SUCCESS_COMPLETED since taking decision with INCOMPLETE status
     *
     * @param request  Http Request
     * @param response Http Response
     * @param sessionDataKey Session data key
     * @param type authenticator type
     * @throws ServletException
     * @throws IOException
     */
    private void sendRequestToFramework(HttpServletRequest request, HttpServletResponse response, String sessionDataKey,
            String type)
            throws ServletException, IOException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    SAML_INBOUND_SERVICE, HAND_OVER_TO_FRAMEWORK);
            diagnosticLogBuilder.resultMessage("Call authentication framework directly via API.")
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM);
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();

        CommonAuthRequestWrapper requestWrapper = new CommonAuthRequestWrapper(request);
        requestWrapper.setParameter(FrameworkConstants.SESSION_DATA_KEY, sessionDataKey);
        requestWrapper.setParameter(FrameworkConstants.RequestParams.TYPE, type);

        CommonAuthResponseWrapper responseWrapper = new CommonAuthResponseWrapper(response);
        commonAuthenticationHandler.doGet(requestWrapper, responseWrapper);

        Object object = request.getAttribute(FrameworkConstants.RequestParams.FLOW_STATUS);
        if (object != null) {
            AuthenticatorFlowStatus status = (AuthenticatorFlowStatus) object;
            if (status == AuthenticatorFlowStatus.INCOMPLETE) {
                if (responseWrapper.isRedirect()) {
                    response.sendRedirect(responseWrapper.getRedirectURL());
                } else {
                    if (responseWrapper.getContent().length > 0) {
                        responseWrapper.write();
                    }
                }
            } else {
                doGet(requestWrapper, response);
            }
        } else {
            requestWrapper.setAttribute(FrameworkConstants.RequestParams.FLOW_STATUS, AuthenticatorFlowStatus.UNKNOWN);
            doGet(requestWrapper, response);
        }
    }

    private void updateSAMLSSOIdCookieConfig(ServletCookie cookie, IdentityCookieConfig
            samlSSOIdCookieConfig, Integer age, boolean isTenantQualifiedCookie) {

        if (samlSSOIdCookieConfig.getDomain() != null) {
            cookie.setDomain(samlSSOIdCookieConfig.getDomain());
        }
        if (samlSSOIdCookieConfig.getPath() != null && !isTenantQualifiedCookie) {
            cookie.setPath(samlSSOIdCookieConfig.getPath());
        }
        if (samlSSOIdCookieConfig.getComment() != null) {
            cookie.setComment(samlSSOIdCookieConfig.getComment());
        }
        if (samlSSOIdCookieConfig.getVersion() > 0) {
            cookie.setVersion(samlSSOIdCookieConfig.getVersion());
        }
        if (samlSSOIdCookieConfig.getSameSite() != null) {
            cookie.setSameSite(samlSSOIdCookieConfig.getSameSite());
        }
        if (age != null) {
            cookie.setMaxAge(age);
        }
        cookie.setHttpOnly(samlSSOIdCookieConfig.isHttpOnly());
        cookie.setSecure(samlSSOIdCookieConfig.isSecure());
    }

    private SAMLSSOServiceProviderDO getServiceProviderConfig(SAMLSSOAuthnReqDTO authnReqDTO) throws IdentityException {

        String issuer = authnReqDTO.getIssuer();
        String tenantDomain = authnReqDTO.getTenantDomain();

        try {
            // Check for SaaS service providers available.
            SSOServiceProviderConfigManager saasServiceProviderConfigManager = SSOServiceProviderConfigManager
                    .getInstance();
            SAMLSSOServiceProviderDO serviceProviderConfigs = saasServiceProviderConfigManager.getServiceProvider
                    (issuer);
            if (serviceProviderConfigs == null) { // Check for service providers registered in tenant

                if (log.isDebugEnabled()) {
                    log.debug("No SaaS SAML service providers found for the issuer : " + issuer + ". Checking for " +
                            "SAML service providers registered in tenant domain : " + tenantDomain);
                }

                int tenantId;
                if (StringUtils.isBlank(tenantDomain)) {
                    tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
                    tenantId = MultitenantConstants.SUPER_TENANT_ID;
                } else {
                    try {
                        tenantId = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
                    } catch (UserStoreException e) {
                        throw new IdentitySAML2SSOException("Error occurred while retrieving tenant id for the " +
                                "tenant domain : " + tenantDomain, e);
                    }
                }

                try {
                    PrivilegedCarbonContext.startTenantFlow();
                    PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext
                            .getThreadLocalCarbonContext();
                    privilegedCarbonContext.setTenantId(tenantId);
                    privilegedCarbonContext.setTenantDomain(tenantDomain);

                    serviceProviderConfigs = IdentitySAMLSSOServiceComponentHolder.getInstance()
                            .getSAMLSSOServiceProviderManager().getServiceProvider(issuer, tenantId);
                    authnReqDTO.setStratosDeployment(false); // not stratos
                } catch (IdentityException e) {
                    throw new IdentitySAML2SSOException("Error occurred while retrieving SAML service provider for "
                            + "issuer : " + issuer + " in tenant domain : " + tenantDomain, e);
                } finally {
                    PrivilegedCarbonContext.endTenantFlow();
                }
            } else {
                authnReqDTO.setStratosDeployment(true); // stratos deployment
            }

            return serviceProviderConfigs;
        } catch (Exception e) {
            throw IdentityException.error(IdentityException.class, "Error while reading service provider " +
                    "configurations for issuer : " + issuer + " in tenant domain : " + tenantDomain, e);
        }
    }

    private void populateAuthnReqDTOWithCachedSessionEntry(SAMLSSOAuthnReqDTO authnReqDTO, SAMLSSOSessionDTO
            sessionDTO) {

        authnReqDTO.setAssertionConsumerURL(sessionDTO.getAssertionConsumerURL());
        authnReqDTO.setId(sessionDTO.getRequestID());
        authnReqDTO.setIssuer(SAMLSSOUtil.splitAppendedTenantDomain(sessionDTO.getIssuer()));
        authnReqDTO.setIssuerQualifier(sessionDTO.getIssuerQualifier());
        authnReqDTO.setSubject(sessionDTO.getSubject());
        authnReqDTO.setRpSessionId(sessionDTO.getRelyingPartySessionId());
        authnReqDTO.setRequestMessageString(sessionDTO.getRequestMessageString());
        authnReqDTO.setQueryString(sessionDTO.getHttpQueryString());
        authnReqDTO.setDestination(sessionDTO.getDestination());
        authnReqDTO.setIdPInitSSOEnabled(sessionDTO.isIdPInitSSO());
        authnReqDTO.setTenantDomain(sessionDTO.getTenantDomain());
        authnReqDTO.setIdPInitSLOEnabled(sessionDTO.isIdPInitSLO());
        if (!(sessionDTO.getAttributeConsumingServiceIndex() < 1)) {
            authnReqDTO.setAttributeConsumingServiceIndex(sessionDTO.getAttributeConsumingServiceIndex());
        }
        authnReqDTO.setAuthenticationContextClassRefList(sessionDTO.getAuthenticationContextClassRefList());
        authnReqDTO.setRequestedAttributes(sessionDTO.getRequestedAttributes());
        authnReqDTO.setRequestedAuthnContextComparison(sessionDTO.getRequestedAuthnContextComparison());
        authnReqDTO.setProperties(sessionDTO.getProperties());
        authnReqDTO.setLoggedInTenantDomain(sessionDTO.getLoggedInTenantDomain());
    }

    private void populateAuthnReqDTOWithRequiredServiceProviderConfigs(SAMLSSOAuthnReqDTO authnReqDTO,
                                                               SAMLSSOServiceProviderDO serviceProviderConfigs) {

        // Set ACS URL from Authentication request.
        String acsUrl = authnReqDTO.getAssertionConsumerURL();
        if (StringUtils.isBlank(acsUrl)) {
            // Authentication request does not include an ACS URL. Set the default ACS URL configured in service
            // provider configurations.
            authnReqDTO.setAssertionConsumerURL(serviceProviderConfigs.getDefaultAssertionConsumerUrl());
        }
        authnReqDTO.setCertAlias(serviceProviderConfigs.getCertAlias());
        authnReqDTO.setDoValidateSignatureInRequests(serviceProviderConfigs.isDoValidateSignatureInRequests());
    }

    private void populateAuthnReqDTOWithAuthenticationResult(SAMLSSOAuthnReqDTO authnReqDTO, AuthenticationResult
            authResult) throws UserStoreException, IdentityException {

        authnReqDTO.setUser(authResult.getSubject());
        authnReqDTO.setClaimMapping(authResult.getClaimMapping());
        if (authResult.getProperty(FrameworkConstants.AUTHENTICATION_CONTEXT_PROPERTIES) != null) {
            List<AuthenticationContextProperty> authenticationContextProperties =
                    (List<AuthenticationContextProperty>) authResult.getProperty(FrameworkConstants
                            .AUTHENTICATION_CONTEXT_PROPERTIES);

            for (AuthenticationContextProperty authenticationContextProperty : authenticationContextProperties) {
                if (SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF.equals(authenticationContextProperty
                        .getPassThroughDataType())) {
                    authnReqDTO.addIdpAuthenticationContextProperty(SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF,
                            authenticationContextProperty);
                }
            }
        }

        if (authResult.getProperty(FrameworkConstants.CREATED_TIMESTAMP) != null &&
                authResult.getProperty(FrameworkConstants.CREATED_TIMESTAMP) instanceof Long) {
            authnReqDTO.setCreatedTimeStamp((long)authResult.getProperty(FrameworkConstants.CREATED_TIMESTAMP));
        }
        authnReqDTO.setIdpSessionIdentifier((String)
                authResult.getProperty(FrameworkConstants.AnalyticsAttributes.SESSION_ID));

        SAMLSSOUtil.setIsSaaSApplication(authResult.isSaaSApp());
        SAMLSSOUtil.setUserTenantDomain(authResult.getSubject().getTenantDomain());
    }

    private void setSPAttributeToRequest(HttpServletRequest req, String issuer, String tenantDomain) {

        try {
            if (StringUtils.isBlank(issuer)) {
                // This is executing in a single logout flow.( samlsso?slo=true). Here it is not possible to identify
                // the service provider name from the issuer.
                return;
            }
            String spName = ApplicationManagementService.getInstance()
                    .getServiceProviderNameByClientId(SAMLSSOUtil.splitAppendedTenantDomain(issuer),
                            IdentityApplicationConstants.Authenticator.SAML2SSO.NAME, tenantDomain);
            req.setAttribute(REQUEST_PARAM_SP, spName);
            req.setAttribute(TENANT_DOMAIN, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            log.error("Error while getting Service provider name for issuer:" + issuer + " in tenant: " +
                    tenantDomain, e);
        }
    }

    private void doFrontChannelSLO(HttpServletRequest request, HttpServletResponse response,
                                   SAMLSSOServiceProviderDO samlssoServiceProviderDO, String sessionIndex,
                                   String originalLogoutRequestIssuer, String originalIssuerLogoutRequestId,
                                   boolean isIdPInitSLO, String relayState, String returnToURL,
                                   String loginTenantDomain) throws IdentityException, IOException, ServletException {

        SessionInfoData sessionInfoData = SAMLSSOUtil.getSessionInfoData(sessionIndex, loginTenantDomain);
        String subject = sessionInfoData.getSubject(originalLogoutRequestIssuer);

        LogoutRequest logoutRequest = SAMLSSOUtil.buildLogoutRequest(samlssoServiceProviderDO, subject, sessionIndex);
        storeFrontChannelSLOParticipantInfo(samlssoServiceProviderDO, originalLogoutRequestIssuer, logoutRequest,
                originalIssuerLogoutRequestId, sessionIndex, isIdPInitSLO, relayState, returnToURL);

        if (SAMLSSOProviderConstants.HTTP_POST_BINDING.
                equals(samlssoServiceProviderDO.getFrontChannelLogoutBinding())) {
            sendPostRequest(request, response, samlssoServiceProviderDO, logoutRequest);
        } else {
            String redirectUrl = createHttpQueryStringForRedirect(logoutRequest, samlssoServiceProviderDO);
            response.sendRedirect(redirectUrl);
        }
    }

    /**
     * This method is used to prepare and send a SAML request message with HTTP POST binding.
     *
     * @param request                  HttpServlet Request.
     * @param response                 HttpServlet Response.
     * @param samlssoServiceProviderDO SAMLSSOServiceProviderDO.
     * @param logoutRequest            Logout Request.
     * @throws IdentityException Error in marshalling or getting SignKeyDataHolder.
     * @throws IOException       Error in post page printing.
     */
    private void sendPostRequest(HttpServletRequest request, HttpServletResponse response,
                                 SAMLSSOServiceProviderDO samlssoServiceProviderDO, LogoutRequest logoutRequest)
            throws IdentityException, IOException, ServletException {

        logoutRequest = SAMLSSOUtil.setSignature(logoutRequest, samlssoServiceProviderDO.getSigningAlgorithmUri(),
                samlssoServiceProviderDO.getDigestAlgorithmUri(), new SignKeyDataHolder(null));
        String encodedRequestMessage = SAMLSSOUtil.encode(SAMLSSOUtil.marshall(logoutRequest));
        String acUrl = logoutRequest.getDestination();
        String spName = resolveAppName();
        printPostPage(request, response, acUrl, encodedRequestMessage, spName);
    }

    private void printPostPage(HttpServletRequest request, HttpServletResponse response, String acUrl,
                               String encodedRequestMessage, String spName)
            throws IOException, ServletException {

        response.setContentType("text/html; charset=" + StandardCharsets.UTF_8.name());
        if (IdentitySAMLSSOServiceComponent.isSAMLSSOResponseJspPageAvailable()) {
            generateSamlPostPageFromJSP(request, response, acUrl, encodedRequestMessage,
                    SAMLSSOConstants.SAML_REQUEST, spName);
        } else if (IdentitySAMLSSOServiceComponent.isSAMLSSOResponseHtmlPageAvailable()) {
            generateSamlPostPage(IdentitySAMLSSOServiceComponent.getSsoRedirectHtml(), response, acUrl,
                    encodedRequestMessage, SAMLSSOConstants.SAML_REQUEST, spName);
        } else {
            generateSamlPostPage(formPostPageTemplate, response, acUrl, encodedRequestMessage,
                    SAMLSSOConstants.SAML_REQUEST, spName);
        }
    }

    private String buildPostPageInputs(String formControlName, String formControlValue) {

        StringBuilder hiddenInputBuilder = new StringBuilder();
        hiddenInputBuilder.append("<!--$params-->\n").append("<input type='hidden' name='").append(formControlName)
                .append("' value='").append(Encode.forHtmlAttribute(formControlValue)).append("'/>");

        return hiddenInputBuilder.toString();
    }

    /**
     * Stores information of front-channel session participants in single logout.
     *
     * @param logoutRequestIssuingSP      Logout request issuing service provider
     * @param originalLogoutRequestIssuer Original logout request issuer
     * @param logoutRequest               Logout request
     * @param initialLogoutRequestId      Logout request id of the original issuer
     * @param sessionIndex                Session index
     * @param isIdPInitSLO                is IdP Initiated Single logout
     * @param relayState                  Relay State
     * @param returnToURL                 Return to URL
     */
    private void storeFrontChannelSLOParticipantInfo(SAMLSSOServiceProviderDO logoutRequestIssuingSP,
                                                     String originalLogoutRequestIssuer,
                                                     LogoutRequest logoutRequest, String initialLogoutRequestId,
                                                     String sessionIndex, boolean isIdPInitSLO, String relayState,
                                                     String returnToURL) {

        FrontChannelSLOParticipantInfo frontChannelSLOParticipantInfo =
                new FrontChannelSLOParticipantInfo(initialLogoutRequestId, originalLogoutRequestIssuer,
                        logoutRequestIssuingSP.getIssuer(), sessionIndex, isIdPInitSLO, relayState, returnToURL);

        FrontChannelSLOParticipantStore.getInstance().addToCache(logoutRequest.getID(), frontChannelSLOParticipantInfo);
    }

    /**
     * Retrieves information of front-channel session participants in single logout.
     *
     * @param logoutRequestId Logout request id.
     * @return Front-Channel SLO Participant Information.
     */
    private FrontChannelSLOParticipantInfo getFrontChannelSLOParticipantInfo(String logoutRequestId) {

        FrontChannelSLOParticipantInfo frontChannelSLOParticipantInfo =
                FrontChannelSLOParticipantStore.getInstance().getValueFromCache(logoutRequestId);

        return frontChannelSLOParticipantInfo;
    }

    /**
     * Removes information of front-channel slo session participant from the store.
     *
     * @param logoutRequestId Logout request id.
     */
    private void removeFrontChannelSLOParticipantInfo(String logoutRequestId) {

        FrontChannelSLOParticipantStore.getInstance().clearCacheEntry(logoutRequestId);
    }

    /**
     * This method is used to prepare a SAML request message as a HTTP query string for HTTP Redirect binding.
     *
     * @param logoutRequest     Logout Request.
     * @param serviceProviderDO SAMLSSOServiceProviderDO.
     * @return Redirect URL.
     * @throws IdentityException Error in marshalling or setting signature to http query string.
     */
    private String createHttpQueryStringForRedirect(LogoutRequest logoutRequest,
                                                    SAMLSSOServiceProviderDO serviceProviderDO)
            throws IdentityException {

        // Convert the SAML logout request object to a string.
        String logoutRequestString = (SAMLSSOUtil.marshall(logoutRequest)).
                replaceAll(SAMLSSOConstants.XML_TAG_REGEX, "").trim();

        StringBuilder httpQueryString = null;
        String signatureAlgorithmUri = serviceProviderDO.getSigningAlgorithmUri();

        String tenantDomain = serviceProviderDO.getTenantDomain();
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        try {
            httpQueryString = new StringBuilder(SAMLSSOConstants.SAML_REQUEST + "=" +
                    URLEncoder.encode(SAMLSSOUtil.compressResponse(logoutRequestString),
                            StandardCharsets.UTF_8.name()));
            httpQueryString.append("&" + SAMLSSOConstants.SIG_ALG + "=" +
                    URLEncoder.encode(signatureAlgorithmUri, StandardCharsets.UTF_8.name()));
            SAMLSSOUtil.addSignatureToHTTPQueryString(httpQueryString, signatureAlgorithmUri,
                    new X509CredentialImpl(tenantDomain));
        } catch (IOException e) {
            throw new IdentityException("Error in compressing the SAML request message.", e);
        }

        String redirectUrl = FrameworkUtils.appendQueryParamsStringToUrl(logoutRequest.getDestination(),
                httpQueryString.toString());

        return redirectUrl;
    }

    /**
     * This method is used to validate destination url sent with SAML request.
     *
     * @param authnReqDTO SAMLSSOAuthenticationRequestDTO.
     * @param req Request
     * @param resp Response
     * @throws IdentityException
     * @throws IOException
     * @throws ServletException
     */
    protected boolean isDestinationUrlValid(SAMLSSOAuthnReqDTO authnReqDTO, HttpServletRequest req,
                                  HttpServletResponse resp) throws ServletException, IdentityException, IOException {

        String tenantDomain = authnReqDTO.getTenantDomain();
        String issuer = authnReqDTO.getIssuer();
        List<String> idpDestinationURLs = SAMLSSOUtil.getDestinationFromTenantDomain(tenantDomain);
        String authDestinationUrl = authnReqDTO.getDestination();
        if (idpDestinationURLs.contains(authDestinationUrl)) {
            if (log.isDebugEnabled()) {
                log.debug("Successfully validated destination of the authentication request " +
                        "of issuer :" + issuer + " in tenant domain : " + tenantDomain);
            }
        } else {
            try {
                URL destinationUrl = new URL(authnReqDTO.getDestination());
                if (destinationUrl.getProtocol().equals(HTTPS_SCHEME) && destinationUrl.getPort() == -1) {
                    authDestinationUrl = new URL(destinationUrl.getProtocol(), destinationUrl
                            .getHost(), DEFAULT_HTTPS_PORT, destinationUrl.getFile()).toString();
                } else if (destinationUrl.getProtocol().equals(HTTP_SCHEME) && destinationUrl
                        .getPort() == -1) {
                    authDestinationUrl = new URL(destinationUrl.getProtocol(), destinationUrl
                            .getHost(), DEFAULT_HTTP_PORT, destinationUrl.getFile()).toString();
                }
            } catch (MalformedURLException e) {
                // This block is reached if the destination url is a relative url. Since spec doesn't
                // restrict this exception will not be handled.
            }
            if (idpDestinationURLs.contains(authDestinationUrl)) {
                if (log.isDebugEnabled()) {
                    log.debug("Successfully validated destination of the authentication request " +
                            "of issuer :" + issuer + " in tenant domain : " + tenantDomain);
                }
            } else {
                String msg = "Destination validation for authentication request failed. " + "Received: " +
                        authDestinationUrl + "." + " Expected one in the list: [" + StringUtils
                        .join(idpDestinationURLs, ',') + "]";
                handleInvalidRequest(msg, authnReqDTO, req, resp);
                return false;
            }
        }

        return true;
    }

    /**
     * This method is used to send notifications if request contains invalid values.
     *
     * @param msg     Error message.
     * @param authnReqDTO SAMLSSOAuthenticationRequestDTO.
     * @param req Request
     * @param resp Response
     * @throws IdentityException
     * @throws IOException
     * @throws ServletException
     */
    private void handleInvalidRequest(String msg, SAMLSSOAuthnReqDTO authnReqDTO, HttpServletRequest req,
                                          HttpServletResponse resp) throws IOException, IdentityException,
            ServletException {

        log.warn(msg);
        List<String> statusCodes = new ArrayList<>();
        statusCodes.add(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR);
        String errorResp = SAMLSSOUtil.buildCompressedErrorResponse(authnReqDTO.getId(), statusCodes, msg,
                authnReqDTO.getAssertionConsumerURL());

        sendNotification(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS, SAMLSSOConstants
                .Notification.EXCEPTION_MESSAGE, authnReqDTO.getAssertionConsumerURL(), req, resp);
    }

    /**
     * This method is used to retrieve logged in tenant domain.
     *
     * @param req HttpServletRequest.
     * @return logged in tenant domain.
     */
    private String getLoggedInTenantDomain(HttpServletRequest req) {

        if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
            return SAMLSSOUtil.getTenantDomainFromThreadLocal();
        }

        String loggedInTenantDomain = req.getParameter(FrameworkConstants.RequestParams.LOGIN_TENANT_DOMAIN);
        if (StringUtils.isBlank(loggedInTenantDomain)) {
            return IdentityTenantUtil.getTenantDomainFromContext();
        }
        return loggedInTenantDomain;
    }

    /**
     * This method is used to resolve application name.
     *
     * @return Application Name.
     */
    private String resolveAppName() {

        String tenantDomain = SAMLSSOUtil.getTenantDomainFromThreadLocal();
        String issuer = SAMLSSOUtil.getIssuerWithQualifierInThreadLocal();

        if (StringUtils.isNotBlank(issuer) && StringUtils.isNotBlank(tenantDomain)) {
            try {
                 return ApplicationManagementService.getInstance()
                        .getServiceProviderNameByClientId(SAMLSSOUtil.splitAppendedTenantDomain(issuer),
                                IdentityApplicationConstants.Authenticator.SAML2SSO.NAME, tenantDomain);
            } catch (IdentityApplicationManagementException e) {
                log.error("Error while getting service provider name for issuer:" + issuer + " in tenant: " +
                        tenantDomain, e);
            }
        }
        return null;
    }

    /**
     * This method is used to check if a request is a ECP request or not.
     *
     * @param req HttpServletRequest.
     * @return if the request is ECP request or not.
     */
    private boolean isSAMLECPRequest(HttpServletRequest req) {

        return SAML_ECP_ENABLED && Boolean.parseBoolean(req.getParameter(SAMLECPConstants.IS_ECP_REQUEST));
    }

    /**
     * This method is used to generate the response for a ECP request.
     *
     * @param resp          HttpServletResponse.
     * @param response      Response message.
     * @param acUrl         Assertion Consumer URL.
     * @throws IOException If sending response fails.
     */
    private void generateResponseForECPRequest(HttpServletResponse resp, String response, String acUrl)
            throws IOException {

        PrintWriter out = resp.getWriter();
        resp.setContentType(MediaType.TEXT_XML);
        resp.setHeader(SAMLSSOConstants.CACHE_CONTROL_PARAM_KEY, "no-store, no-cache, must-revalidate, private");
        String samlResponse = new String(Base64.getDecoder().decode(response))
                .replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", StringUtils.EMPTY);
        try {
            String soapResponse = SAMLSOAPUtils.createSOAPMessage(samlResponse, acUrl);
            if (log.isDebugEnabled()) {
                log.debug(soapResponse);
            }
            out.print(soapResponse);
        } catch (TransformerException | SOAPException e) {
            SAMLSOAPUtils.sendSOAPFault(resp, e.getMessage(), SAMLECPConstants.FaultCodes.SOAP_FAULT_CODE_SERVER);
            String message = "Error Generating the SOAP Response";
            log.error(message, e);
        }
    }

    /**
     * This method is used to generate a error response for a ECP request.
     *
     * @param resp          HttpServletResponse.
     * @param errorResp     Error response message.
     * @param acUrl         Assertion Consumer URL.
     * @throws IOException If sending response fails.
     */
    private void sendNotificationForECPRequest(HttpServletResponse resp, String errorResp, String acUrl)
            throws IOException {

        PrintWriter out = resp.getWriter();
        try {
            String soapResp = SAMLSOAPUtils.createSOAPMessage(SAMLSSOUtil.decode(errorResp).
                    replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", StringUtils.EMPTY), acUrl);
            if (log.isDebugEnabled()) {
                log.debug(soapResp);
            }
            out.print(soapResp);
        } catch (IdentityException e) {
            SAMLSOAPUtils.sendSOAPFault(resp, e.getMessage(), SAMLECPConstants.FaultCodes.SOAP_FAULT_CODE_CLIENT);
            String err = "Error when decoding the error response.";
            log.error(err, e);
        } catch (SOAPException | TransformerException e) {
            SAMLSOAPUtils.sendSOAPFault(resp, e.getMessage(), SAMLECPConstants.FaultCodes.SOAP_FAULT_CODE_SERVER);
            String err = "Error Generating the SOAP Response";
            log.error(err, e);
        }
    }

    /**
     * To retrieve session context of the given session identifier.
     *
     * @param sessionIdentifier Session identifier.
     * @param loginTenantDomain Login tenant domain.
     * @return Session context for the given session identifier.
     */
    private SessionContext getSessionContext(String sessionIdentifier, String loginTenantDomain) {

        if (StringUtils.isNotBlank(sessionIdentifier) && StringUtils.isNotBlank(loginTenantDomain)) {
            return FrameworkUtils.getSessionContextFromCache(sessionIdentifier, loginTenantDomain);
        }
        return null;
    }
}
