/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml.servlet;

import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SAMLSSOService;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSORespDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOSessionDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.util.Properties;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Tests the SAML authentication failure handling in
 * {@link SAMLSSOProviderServlet#handleAuthenticationReponseFromFramework}. When the
 * {@code SSOService.SendSAMLAuthFailureResponseToSP} config is enabled and a valid ACS URL is present, the SAML error
 * response is POSTed back to the SP's Assertion Consumer Service URL; otherwise the flow falls back to the generic
 * IdP notification page.
 */
public class SAMLSSOProviderServletAuthFailureResponseTest {

    private static final String TEST_ACS_URL = "https://localhost:9443/acs";
    private static final String TEST_ISSUER = "test-issuer";
    // Base64-safe payload so it survives Encode.forHtmlAttribute untouched and can be asserted verbatim.
    private static final String TEST_ERROR_RESPONSE = "PHNhbWxFcnJvcj48L3NhbWxFcnJvcj4=";

    @DataProvider(name = "sendAuthFailureResponseConfig")
    public Object[][] sendAuthFailureResponseConfig() {

        return new Object[][]{
                // sendToSpEnabled -> when true, error response is POSTed to the SP; when false, notification page.
                {true},
                {false},
        };
    }

    @Test(dataProvider = "sendAuthFailureResponseConfig")
    public void testHandleAuthenticationFailureResponse(boolean sendToSpEnabled) throws Exception {

        try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
             MockedStatic<SAMLSSOUtil> samlssoUtil = mockStatic(SAMLSSOUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<SSOServiceProviderConfigManager> spConfigManagerStatic =
                     mockStatic(SSOServiceProviderConfigManager.class)) {

            loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

            // Short-circuit the SP config lookup so the flow reaches the auth-failure branch without registry access.
            SSOServiceProviderConfigManager spConfigManager = mock(SSOServiceProviderConfigManager.class);
            spConfigManagerStatic.when(SSOServiceProviderConfigManager::getInstance).thenReturn(spConfigManager);
            SAMLSSOServiceProviderDO serviceProviderDO = mock(SAMLSSOServiceProviderDO.class);
            when(spConfigManager.getServiceProvider(any())).thenReturn(serviceProviderDO);

            samlssoUtil.when(() -> SAMLSSOUtil.splitAppendedTenantDomain(anyString())).thenReturn(TEST_ISSUER);
            samlssoUtil.when(SAMLSSOUtil::isSendAuthFailureResponseToSPEnabled).thenReturn(sendToSpEnabled);
            samlssoUtil.when(() -> SAMLSSOUtil.buildErrorResponse(anyString(), anyList(), anyString(), anyString()))
                    .thenReturn(TEST_ERROR_RESPONSE);
            samlssoUtil.when(() -> SAMLSSOUtil.buildCompressedErrorResponse(anyString(), anyList(), anyString(),
                    anyString())).thenReturn(TEST_ERROR_RESPONSE);
            samlssoUtil.when(SAMLSSOUtil::getNotificationEndpoint)
                    .thenReturn("https://localhost:9443/authenticationendpoint/samlsso_notification.do");

            frameworkUtils.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                    .thenReturn("https://localhost:9443/authenticationendpoint/samlsso_notification.do?params");
            frameworkUtils.when(() -> FrameworkUtils.getRedirectURL(anyString(), any(HttpServletRequest.class)))
                    .thenReturn("https://localhost:9443/authenticationendpoint/samlsso_notification.do?params");

            HttpServletRequest request = mock(HttpServletRequest.class);
            AuthenticationResult authenticationResult = mock(AuthenticationResult.class);
            when(authenticationResult.isAuthenticated()).thenReturn(false);
            when(request.getAttribute(FrameworkConstants.RequestAttribute.AUTH_RESULT))
                    .thenReturn(authenticationResult);
            // Non-empty relay state so the notification path does not fall back to the session cache.
            when(request.getParameter(SAMLSSOConstants.RELAY_STATE)).thenReturn("relayState");

            HttpServletResponse response = mock(HttpServletResponse.class);
            StringWriter stringWriter = new StringWriter();
            when(response.getWriter()).thenReturn(new PrintWriter(stringWriter));

            SAMLSSOSessionDTO sessionDTO = mock(SAMLSSOSessionDTO.class);
            when(sessionDTO.getAssertionConsumerURL()).thenReturn(TEST_ACS_URL);
            when(sessionDTO.getIssuer()).thenReturn(TEST_ISSUER);
            when(sessionDTO.getTenantDomain()).thenReturn("");
            when(sessionDTO.getRequestID()).thenReturn("test-request-id");
            when(sessionDTO.getRelayState()).thenReturn("relayState");
            when(sessionDTO.getProperties()).thenReturn(new Properties());
            SAMLSSOReqValidationResponseDTO validationRespDTO = mock(SAMLSSOReqValidationResponseDTO.class);
            when(validationRespDTO.isPassive()).thenReturn(false);
            when(validationRespDTO.getSubject()).thenReturn("test-subject");
            when(sessionDTO.getValidationRespDTO()).thenReturn(validationRespDTO);

            SAMLSSOProviderServlet servlet = new SAMLSSOProviderServlet();
            Method method = SAMLSSOProviderServlet.class.getDeclaredMethod(
                    "handleAuthenticationReponseFromFramework",
                    HttpServletRequest.class, HttpServletResponse.class, String.class, SAMLSSOSessionDTO.class);
            method.setAccessible(true);
            method.invoke(servlet, request, response, "test-session-id", sessionDTO);

            if (sendToSpEnabled) {
                // Error response is built for and POSTed to the SP's ACS URL.
                samlssoUtil.verify(() -> SAMLSSOUtil.buildErrorResponse(anyString(), anyList(), anyString(),
                        eq(TEST_ACS_URL)));
                String renderedPage = stringWriter.toString();
                assertTrue(renderedPage.contains("samlsso-response-form"),
                        "An auto-submitting POST form should be rendered for the SP.");
                assertTrue(renderedPage.contains(TEST_ACS_URL),
                        "The POST form should target the SP's ACS URL.");
                assertTrue(renderedPage.contains(TEST_ERROR_RESPONSE),
                        "The POST form should carry the SAML error response.");
                assertGuardedResponsePage(renderedPage);
                verify(response, never()).sendRedirect(anyString());
            } else {
                // Fallback path renders the generic IdP notification page via a redirect.
                samlssoUtil.verify(() -> SAMLSSOUtil.buildCompressedErrorResponse(anyString(), anyList(), anyString(),
                        eq(TEST_ACS_URL)));
                samlssoUtil.verify(() -> SAMLSSOUtil.buildErrorResponse(anyString(), anyList(), anyString(),
                        anyString()), never());
                verify(response).sendRedirect(anyString());
            }
        }
    }

    /**
     * Covers the failure path taken when the user is authenticated but the SAML session is not established
     * (i.e. {@code authRespDTO.isSessionEstablished()} is {@code false}). When the config is enabled the deflated
     * error response is re-encoded for POST binding and sent to the SP; otherwise the notification page is used.
     */
    @Test(dataProvider = "sendAuthFailureResponseConfig")
    public void testHandleSessionNotEstablishedFailureResponse(boolean sendToSpEnabled) throws Exception {

        SAMLSSORespDTO authRespDTO = mock(SAMLSSORespDTO.class);
        when(authRespDTO.isSessionEstablished()).thenReturn(false);
        when(authRespDTO.getRespString()).thenReturn("deflatedErrorResponse");
        when(authRespDTO.getAssertionConsumerURL()).thenReturn(TEST_ACS_URL);

        try (MockedStatic<LoggerUtils> loggerUtils = mockStatic(LoggerUtils.class);
             MockedStatic<SAMLSSOUtil> samlssoUtil = mockStatic(SAMLSSOUtil.class);
             MockedStatic<IdentityUtil> identityUtil = mockStatic(IdentityUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = mockStatic(FrameworkUtils.class);
             MockedStatic<PrivilegedCarbonContext> carbonContext = mockStatic(PrivilegedCarbonContext.class);
             MockedStatic<SSOServiceProviderConfigManager> spConfigManagerStatic =
                     mockStatic(SSOServiceProviderConfigManager.class);
             MockedConstruction<SAMLSSOService> serviceConstruction = Mockito.mockConstruction(SAMLSSOService.class,
                     (serviceMock, context) -> when(serviceMock.authenticate(any(), any(), anyBoolean(), any(), any()))
                             .thenReturn(authRespDTO))) {

            loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

            // Short-circuit the SP config lookup so the flow reaches the auth-failure branch without registry access.
            SSOServiceProviderConfigManager spConfigManager = mock(SSOServiceProviderConfigManager.class);
            spConfigManagerStatic.when(SSOServiceProviderConfigManager::getInstance).thenReturn(spConfigManager);
            when(spConfigManager.getServiceProvider(any())).thenReturn(mock(SAMLSSOServiceProviderDO.class));

            PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
            carbonContext.when(PrivilegedCarbonContext::getThreadLocalCarbonContext)
                    .thenReturn(privilegedCarbonContext);

            samlssoUtil.when(() -> SAMLSSOUtil.splitAppendedTenantDomain(anyString())).thenReturn(TEST_ISSUER);
            samlssoUtil.when(SAMLSSOUtil::isSendAuthFailureResponseToSPEnabled).thenReturn(sendToSpEnabled);
            // prepareErrorResponseForPostBinding() re-encodes the deflated response: encode(decode(resp)).
            samlssoUtil.when(() -> SAMLSSOUtil.decode(anyString())).thenReturn("inflatedErrorResponse");
            samlssoUtil.when(() -> SAMLSSOUtil.encode(anyString())).thenReturn(TEST_ERROR_RESPONSE);
            samlssoUtil.when(SAMLSSOUtil::getNotificationEndpoint)
                    .thenReturn("https://localhost:9443/authenticationendpoint/samlsso_notification.do");

            frameworkUtils.when(() -> FrameworkUtils.appendQueryParamsStringToUrl(anyString(), anyString()))
                    .thenReturn("https://localhost:9443/authenticationendpoint/samlsso_notification.do?params");
            frameworkUtils.when(() -> FrameworkUtils.getRedirectURL(anyString(), any(HttpServletRequest.class)))
                    .thenReturn("https://localhost:9443/authenticationendpoint/samlsso_notification.do?params");

            HttpServletRequest request = mock(HttpServletRequest.class);
            AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
            when(authenticatedUser.getTenantDomain()).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            AuthenticationResult authenticationResult = mock(AuthenticationResult.class);
            when(authenticationResult.isAuthenticated()).thenReturn(true);
            when(authenticationResult.getSubject()).thenReturn(authenticatedUser);
            when(request.getAttribute(FrameworkConstants.RequestAttribute.AUTH_RESULT))
                    .thenReturn(authenticationResult);
            when(request.getParameter(SAMLSSOConstants.RELAY_STATE)).thenReturn("relayState");

            HttpServletResponse response = mock(HttpServletResponse.class);
            StringWriter stringWriter = new StringWriter();
            when(response.getWriter()).thenReturn(new PrintWriter(stringWriter));

            SAMLSSOSessionDTO sessionDTO = mock(SAMLSSOSessionDTO.class);
            when(sessionDTO.getAssertionConsumerURL()).thenReturn(TEST_ACS_URL);
            when(sessionDTO.getIssuer()).thenReturn(TEST_ISSUER);
            when(sessionDTO.getTenantDomain()).thenReturn("");
            when(sessionDTO.getRequestID()).thenReturn("test-request-id");
            when(sessionDTO.getRelayState()).thenReturn("relayState");
            when(sessionDTO.getProperties()).thenReturn(new Properties());
            SAMLSSOReqValidationResponseDTO validationRespDTO = mock(SAMLSSOReqValidationResponseDTO.class);
            when(validationRespDTO.getSubject()).thenReturn("test-subject");
            when(sessionDTO.getValidationRespDTO()).thenReturn(validationRespDTO);

            SAMLSSOProviderServlet servlet = new SAMLSSOProviderServlet();
            Method method = SAMLSSOProviderServlet.class.getDeclaredMethod(
                    "handleAuthenticationReponseFromFramework",
                    HttpServletRequest.class, HttpServletResponse.class, String.class, SAMLSSOSessionDTO.class);
            method.setAccessible(true);
            method.invoke(servlet, request, response, "test-session-id", sessionDTO);

            if (sendToSpEnabled) {
                // The deflated response is re-encoded (base64 only) and POSTed to the SP's ACS URL.
                samlssoUtil.verify(() -> SAMLSSOUtil.decode("deflatedErrorResponse"));
                String renderedPage = stringWriter.toString();
                assertTrue(renderedPage.contains("samlsso-response-form"),
                        "An auto-submitting POST form should be rendered for the SP.");
                assertTrue(renderedPage.contains(TEST_ACS_URL),
                        "The POST form should target the SP's ACS URL.");
                assertTrue(renderedPage.contains(TEST_ERROR_RESPONSE),
                        "The POST form should carry the re-encoded SAML error response.");
                assertGuardedResponsePage(renderedPage);
                verify(response, never()).sendRedirect(anyString());
            } else {
                // Fallback path renders the generic IdP notification page via a redirect.
                samlssoUtil.verify(() -> SAMLSSOUtil.decode(anyString()), never());
                verify(response).sendRedirect(anyString());
            }
        }
    }

    private void assertGuardedResponsePage(String renderedPage) {

        assertTrue(renderedPage.contains("onload=\"javascript:submitSamlResponse()\""),
                "The rendered POST page should auto-submit through the guarded function.");
        assertTrue(renderedPage.contains("function submitSamlResponse()"),
                "The rendered POST page should include the guarded submit function.");
        assertTrue(renderedPage.contains("id=\"fallback-submit\" style=\"display:none;\""),
                "The fallback submit control should be hidden during the initial auto-submit window.");
        assertTrue(renderedPage.contains("href=\"javascript:submitSamlResponse()\""),
                "The fallback link should use the guarded submit function.");
        assertTrue(renderedPage.contains("setTimeout(function()"),
                "The guarded submit function should delay fallback availability.");
        assertTrue(renderedPage.contains("submitted = false;"),
                "The guarded submit function should reset after the fallback delay.");
        assertTrue(renderedPage.contains("<noscript>") && renderedPage.contains("type=\"submit\""),
                "A JavaScript-disabled user should have a form submit control.");
        assertFalse(renderedPage.contains("href=\"javascript:document.getElementById('samlsso-response-form')" +
                        ".submit()\""),
                "The fallback link should not directly submit the form.");
    }
}
