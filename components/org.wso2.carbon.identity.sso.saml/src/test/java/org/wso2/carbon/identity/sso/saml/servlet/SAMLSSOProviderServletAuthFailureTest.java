/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com). All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at http://www.apache.org/licenses/LICENSE-2.0
 */

package org.wso2.carbon.identity.sso.saml.servlet;

import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOSessionDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Properties;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Tests for the authentication-failure branch in
 * {@link SAMLSSOProviderServlet#handleAuthenticationReponseFromFramework}.
 *
 * Regression coverage for https://github.com/wso2/product-is/issues/27601:
 * when the framework returns a non-authenticated AuthenticationResult during a
 * SAML SSO flow (e.g. user cancels FIDO2 step), the IdP must build a
 * POST-binding SAML error response and auto-submit it to the SP's ACS rather
 * than forwarding to the dead-end samlsso_notification.jsp page.
 */
public class SAMLSSOProviderServletAuthFailureTest {

    private static final String SENTINEL_BUILD_ERROR_RESPONSE = "SENTINEL_BUILD_ERROR_RESPONSE";
    private static final String SENTINEL_BUILD_COMPRESSED_ERROR_RESPONSE = "SENTINEL_BUILD_COMPRESSED_ERROR_RESPONSE";
    private static final String ACS_URL = "https://sp.example.org/acs";
    private static final String REQUEST_ID = "saml-req-001";
    private static final String ISSUER = "saml-fido-test";
    private static final String RELAY_STATE = "relay-state-001";
    private static final String SUBJECT = "admin";

    @Test
    public void testAuthFailureWithAcsUrl_buildsErrorResponseAndAutoPostsToAcs() throws Exception {

        try (MockedStatic<SAMLSSOUtil> samlssoUtil = Mockito.mockStatic(SAMLSSOUtil.class);
             MockedStatic<LoggerUtils> loggerUtils = Mockito.mockStatic(LoggerUtils.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
             MockedStatic<SSOServiceProviderConfigManager> ssoCfgMgr =
                     Mockito.mockStatic(SSOServiceProviderConfigManager.class)) {

            SAMLSSOSessionDTO sessionDTO = prepareSessionDTO(ACS_URL, false);
            HttpServletRequest request = prepareRequestWithFailedAuthResult();
            HttpServletResponse response = mock(HttpServletResponse.class);

            setupCommonStaticStubs(samlssoUtil, loggerUtils, frameworkUtils, ssoCfgMgr, ACS_URL);

            // The decision we want to verify: buildErrorResponse (auto-post to SP) must be
            // invoked, NOT buildCompressedErrorResponse (render notification JSP).
            // Throw a sentinel from buildErrorResponse so the downstream sendResponse path
            // (which depends on collaborators we don't need to exercise here) is short-circuited.
            samlssoUtil.when(() -> SAMLSSOUtil.buildErrorResponse(
                    nullable(String.class), anyList(), nullable(String.class), nullable(String.class)))
                    .thenThrow(new RuntimeException(SENTINEL_BUILD_ERROR_RESPONSE));
            samlssoUtil.when(() -> SAMLSSOUtil.buildCompressedErrorResponse(
                    nullable(String.class), anyList(), nullable(String.class), nullable(String.class)))
                    .thenThrow(new RuntimeException(SENTINEL_BUILD_COMPRESSED_ERROR_RESPONSE));

            SAMLSSOProviderServlet servlet = new SAMLSSOProviderServlet();
            InvocationTargetException thrown = null;
            try {
                invokeHandleAuthenticationReponseFromFramework(servlet, request, response, sessionDTO);
                fail("Expected one of the SAMLSSOUtil error-response builders to be invoked.");
            } catch (InvocationTargetException e) {
                thrown = e;
            }

            assertNotNull(thrown, "Expected InvocationTargetException from sentinel throw.");
            Throwable cause = thrown.getCause();
            assertNotNull(cause, "Sentinel cause must be present.");
            assertEquals(cause.getMessage(), SENTINEL_BUILD_ERROR_RESPONSE,
                    "When ACS URL is present, the fix must take the buildErrorResponse branch (auto-POST to ACS) "
                            + "instead of the legacy buildCompressedErrorResponse/sendNotification branch.");

            ArgumentCaptor<String> idCaptor = ArgumentCaptor.forClass(String.class);
            ArgumentCaptor<List<String>> codesCaptor = ArgumentCaptor.forClass(List.class);
            ArgumentCaptor<String> acsCaptor = ArgumentCaptor.forClass(String.class);
            samlssoUtil.verify(() -> SAMLSSOUtil.buildErrorResponse(
                    idCaptor.capture(), codesCaptor.capture(), anyString(), acsCaptor.capture()), times(1));
            assertEquals(idCaptor.getValue(), REQUEST_ID);
            assertEquals(acsCaptor.getValue(), ACS_URL);
            List<String> codes = codesCaptor.getValue();
            assertTrue(codes.contains(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE),
                    "Status codes must contain AUTHN_FAILURE.");
            assertTrue(codes.contains(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR),
                    "Status codes must contain IDENTITY_PROVIDER_ERROR as the top-level status.");

            samlssoUtil.verify(() -> SAMLSSOUtil.buildCompressedErrorResponse(
                    nullable(String.class), anyList(), nullable(String.class), nullable(String.class)), times(0));
        }
    }

    @Test
    public void testAuthFailureWithoutAcsUrl_fallsBackToNotificationPath() throws Exception {

        try (MockedStatic<SAMLSSOUtil> samlssoUtil = Mockito.mockStatic(SAMLSSOUtil.class);
             MockedStatic<LoggerUtils> loggerUtils = Mockito.mockStatic(LoggerUtils.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
             MockedStatic<SSOServiceProviderConfigManager> ssoCfgMgr =
                     Mockito.mockStatic(SSOServiceProviderConfigManager.class)) {

            // Empty ACS URL on the session AND no default ACS in SP config → fallback branch
            // (legacy buildCompressedErrorResponse/sendNotification path).
            SAMLSSOSessionDTO sessionDTO = prepareSessionDTO(null, false);
            HttpServletRequest request = prepareRequestWithFailedAuthResult();
            HttpServletResponse response = mock(HttpServletResponse.class);

            setupCommonStaticStubs(samlssoUtil, loggerUtils, frameworkUtils, ssoCfgMgr, null);

            samlssoUtil.when(() -> SAMLSSOUtil.buildErrorResponse(
                    nullable(String.class), anyList(), nullable(String.class), nullable(String.class)))
                    .thenThrow(new RuntimeException(SENTINEL_BUILD_ERROR_RESPONSE));
            samlssoUtil.when(() -> SAMLSSOUtil.buildCompressedErrorResponse(
                    nullable(String.class), anyList(), nullable(String.class), nullable(String.class)))
                    .thenThrow(new RuntimeException(SENTINEL_BUILD_COMPRESSED_ERROR_RESPONSE));

            SAMLSSOProviderServlet servlet = new SAMLSSOProviderServlet();
            InvocationTargetException thrown = null;
            try {
                invokeHandleAuthenticationReponseFromFramework(servlet, request, response, sessionDTO);
                fail("Expected one of the SAMLSSOUtil error-response builders to be invoked.");
            } catch (InvocationTargetException e) {
                thrown = e;
            }

            assertNotNull(thrown);
            Throwable cause = thrown.getCause();
            assertNotNull(cause);
            assertEquals(cause.getMessage(), SENTINEL_BUILD_COMPRESSED_ERROR_RESPONSE,
                    "When ACS URL is blank, the fallback buildCompressedErrorResponse branch must be taken "
                            + "(preserving legacy behaviour).");

            samlssoUtil.verify(() -> SAMLSSOUtil.buildErrorResponse(
                    nullable(String.class), anyList(), nullable(String.class), nullable(String.class)), times(0));
        }
    }

    @Test
    public void testPassiveAuthFailure_stillUsesBuildErrorResponse() throws Exception {

        // Passive-mode authentication failure has its own pre-existing branch that already calls
        // buildErrorResponse + sendResponse. This test guards against accidentally regressing it
        // while modifying the neighbouring user-cancel branch.
        try (MockedStatic<SAMLSSOUtil> samlssoUtil = Mockito.mockStatic(SAMLSSOUtil.class);
             MockedStatic<LoggerUtils> loggerUtils = Mockito.mockStatic(LoggerUtils.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class);
             MockedStatic<SSOServiceProviderConfigManager> ssoCfgMgr =
                     Mockito.mockStatic(SSOServiceProviderConfigManager.class)) {

            SAMLSSOSessionDTO sessionDTO = prepareSessionDTO(ACS_URL, true);
            HttpServletRequest request = prepareRequestWithFailedAuthResult();
            HttpServletResponse response = mock(HttpServletResponse.class);

            setupCommonStaticStubs(samlssoUtil, loggerUtils, frameworkUtils, ssoCfgMgr, ACS_URL);

            samlssoUtil.when(() -> SAMLSSOUtil.buildErrorResponse(
                    nullable(String.class), anyList(), nullable(String.class), nullable(String.class)))
                    .thenThrow(new RuntimeException(SENTINEL_BUILD_ERROR_RESPONSE));
            samlssoUtil.when(() -> SAMLSSOUtil.buildCompressedErrorResponse(
                    nullable(String.class), anyList(), nullable(String.class), nullable(String.class)))
                    .thenThrow(new RuntimeException(SENTINEL_BUILD_COMPRESSED_ERROR_RESPONSE));

            SAMLSSOProviderServlet servlet = new SAMLSSOProviderServlet();
            InvocationTargetException thrown = null;
            try {
                invokeHandleAuthenticationReponseFromFramework(servlet, request, response, sessionDTO);
                fail("Expected buildErrorResponse sentinel for passive-auth failure.");
            } catch (InvocationTargetException e) {
                thrown = e;
            }

            assertNotNull(thrown);
            assertEquals(thrown.getCause().getMessage(), SENTINEL_BUILD_ERROR_RESPONSE);

            ArgumentCaptor<List<String>> codesCaptor = ArgumentCaptor.forClass(List.class);
            samlssoUtil.verify(() -> SAMLSSOUtil.buildErrorResponse(
                    anyString(), codesCaptor.capture(), anyString(), anyString()), times(1));
            assertTrue(codesCaptor.getValue().contains(SAMLSSOConstants.StatusCodes.NO_PASSIVE),
                    "Passive-mode failure must carry NoPassive status code (unchanged by the fix).");
        }
    }

    private void setupCommonStaticStubs(MockedStatic<SAMLSSOUtil> samlssoUtil,
                                        MockedStatic<LoggerUtils> loggerUtils,
                                        MockedStatic<FrameworkUtils> frameworkUtils,
                                        MockedStatic<SSOServiceProviderConfigManager> ssoCfgMgr,
                                        String defaultAcsUrl) {

        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);

        samlssoUtil.when(() -> SAMLSSOUtil.splitAppendedTenantDomain(anyString()))
                .thenAnswer(inv -> inv.getArgument(0));

        frameworkUtils.when(() -> FrameworkUtils.getAuthenticationResultFromCache(anyString()))
                .thenReturn((AuthenticationResultCacheEntry) null);

        // Return a non-null SaaS SP config so getServiceProviderConfig skips the
        // PrivilegedCarbonContext tenant-flow branch (that class is not instrumentable
        // under the inline mock-maker in this JVM).
        SAMLSSOServiceProviderDO spDO = mock(SAMLSSOServiceProviderDO.class);
        when(spDO.getDefaultAssertionConsumerUrl()).thenReturn(defaultAcsUrl);
        when(spDO.getCertAlias()).thenReturn(null);
        when(spDO.isDoValidateSignatureInRequests()).thenReturn(false);

        SSOServiceProviderConfigManager cfgMgr = mock(SSOServiceProviderConfigManager.class);
        when(cfgMgr.getServiceProvider(anyString())).thenReturn(spDO);
        ssoCfgMgr.when(SSOServiceProviderConfigManager::getInstance).thenReturn(cfgMgr);
    }

    private SAMLSSOSessionDTO prepareSessionDTO(String acsUrl, boolean passive) {

        SAMLSSOReqValidationResponseDTO validationDTO = mock(SAMLSSOReqValidationResponseDTO.class);
        when(validationDTO.isPassive()).thenReturn(passive);
        when(validationDTO.getSubject()).thenReturn(SUBJECT);

        SAMLSSOSessionDTO sessionDTO = mock(SAMLSSOSessionDTO.class);
        when(sessionDTO.getAssertionConsumerURL()).thenReturn(acsUrl);
        when(sessionDTO.getValidationRespDTO()).thenReturn(validationDTO);
        // Blank tenant domain → code takes the super-tenant short-circuit (no realm service call).
        when(sessionDTO.getTenantDomain()).thenReturn("");
        when(sessionDTO.getRelayState()).thenReturn(RELAY_STATE);
        when(sessionDTO.getIssuer()).thenReturn(ISSUER);
        when(sessionDTO.getRequestID()).thenReturn(REQUEST_ID);
        when(sessionDTO.getSubject()).thenReturn(SUBJECT);
        when(sessionDTO.getProperties()).thenReturn(new Properties());
        return sessionDTO;
    }

    private HttpServletRequest prepareRequestWithFailedAuthResult() {

        AuthenticationResult authResult = mock(AuthenticationResult.class);
        when(authResult.isAuthenticated()).thenReturn(false);
        when(authResult.getProperty(FrameworkConstants.SESSION_AUTH_HISTORY)).thenReturn(null);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getAttribute(FrameworkConstants.RequestAttribute.AUTH_RESULT)).thenReturn(authResult);
        return request;
    }

    private void invokeHandleAuthenticationReponseFromFramework(SAMLSSOProviderServlet servlet,
                                                                HttpServletRequest req,
                                                                HttpServletResponse resp,
                                                                SAMLSSOSessionDTO sessionDTO)
            throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {

        Method m = SAMLSSOProviderServlet.class.getDeclaredMethod(
                "handleAuthenticationReponseFromFramework",
                HttpServletRequest.class, HttpServletResponse.class, String.class, SAMLSSOSessionDTO.class);
        m.setAccessible(true);
        m.invoke(servlet, req, resp, "session-id-1", sessionDTO);
    }
}
