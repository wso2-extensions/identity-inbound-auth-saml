package org.wso2.carbon.identity.sso.saml.servlet;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOSessionDTO;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.TestConstants;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import org.mockito.ArgumentCaptor;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import javax.servlet.http.Cookie;

import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

public class SAMLSSOProviderServletTest {

    private HttpServletRequest request = mock(HttpServletRequest.class);
    private HttpServletResponse response = mock(HttpServletResponse.class);
    private SAMLSSOAuthnReqDTO authnReqDTO = mock(SAMLSSOAuthnReqDTO.class);
    private SAMLSSOProviderServlet samlssoProviderServlet = new SAMLSSOProviderServlet();
    private SAMLSSOSessionDTO samlssoSessionDTO = mock(SAMLSSOSessionDTO.class);
    private SAMLSSOAuthnReqDTO samlssoAuthnReqDTO = mock(SAMLSSOAuthnReqDTO.class);

    @DataProvider(name = "testValidateDestination")
    public static Object[][] testValidateDestination() {

        return new Object[][]{
                {"https://localhost:9443/samlsso", Collections.singletonList("https://localhost:9443/samlsso"), true},
                {"https://localhost/samlsso", Collections.singletonList("https://localhost:443/samlsso"), true},
                {"http://localhost/samlsso", Collections.singletonList("http://localhost:80/samlsso"), true},
        };
    }

//    @Test(dataProvider = "testValidateDestination")
    public void testDestinationValidate(String providedDestinationUrl, List<String> idpDestinationUrls, boolean expected)
            throws Exception {

        try (MockedStatic<SAMLSSOUtil> ssoUtil = Mockito.mockStatic(SAMLSSOUtil.class)) {
            ssoUtil.when(() -> SAMLSSOUtil.getDestinationFromTenantDomain(anyString())).thenReturn(idpDestinationUrls);
            when(authnReqDTO.getDestination()).thenReturn(providedDestinationUrl);

            boolean isValid = samlssoProviderServlet.isDestinationUrlValid(authnReqDTO, request, response);
            assertEquals(isValid, expected);
        }
    }

    @Test
    public void testNullAuthenticationResult() throws Exception {

        try {
            Method m = SAMLSSOProviderServlet.class.getDeclaredMethod("populateAuthenticationContextClassRefResult",
                    AuthenticationResult.class, SAMLSSOSessionDTO.class, SAMLSSOAuthnReqDTO.class);
            m.setAccessible(true);
            m.invoke(samlssoProviderServlet, (AuthenticationResult) null, samlssoSessionDTO, samlssoAuthnReqDTO);
        } catch (NullPointerException e) {
            fail("Authentication Result can be null. Check for null value should be added to avoid Null pointer " +
                    "exceptions.");
        }
    }

    @DataProvider(name = "doubleEncodingConfigs")
    public static Object[][] doubleEncodingConfigs() {
        String artifact = "artifact+plus";
        String relayState = "relay state";
        return new Object[][]{
                // double encoding disabled
                {"true", artifact, urlEncode(relayState)},
                // double encoding enabled
                {"false", urlEncode(artifact), urlEncode(relayState)}
        };
    }

    @Test(dataProvider = "doubleEncodingConfigs")
    public void testDoubleEncodingHandling(String doubleEncodingDisabledConfig, String expectedArtifact,
                                           String expectedRelayState) throws Exception {

        String artifact = "artifact+plus";
        String relayState = "relay state";
        reset(response);

        try (MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class)) {

            identityUtil.when(() -> IdentityUtil.getProperty(
                    IdentityConstants.ServerConfig.SAML2_ARTIFACT_DOUBLE_ENCODING_DISABLED))
                    .thenReturn(doubleEncodingDisabledConfig);
            frameworkUtils.when(() -> FrameworkUtils.appendQueryParamsToUrl(anyString(), anyMap()))
                    .thenAnswer(invocation -> {
                        @SuppressWarnings("unchecked")
                        java.util.Map<String, String> params = invocation.getArgument(1);
                        assertEquals(params.get(SAMLSSOConstants.SAML_ART), expectedArtifact);
                        assertEquals(params.get(SAMLSSOConstants.RELAY_STATE), expectedRelayState);
                        return "redirectUrl";
                    });

            Method method = SAMLSSOProviderServlet.class.getDeclaredMethod("sendArtifact",
                    HttpServletResponse.class, String.class, String.class, String.class);
            method.setAccessible(true);
            method.invoke(samlssoProviderServlet, response, relayState, artifact, "http://example.com/acs");

            verify(response).addHeader(SAMLSSOConstants.PRAGMA_PARAM_KEY,
                    SAMLSSOConstants.CACHE_CONTROL_VALUE_NO_CACHE);
            verify(response).addHeader(SAMLSSOConstants.CACHE_CONTROL_PARAM_KEY,
                    SAMLSSOConstants.CACHE_CONTROL_VALUE_NO_CACHE);
            verify(response).sendRedirect("redirectUrl");
        }
    }

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException("UTF-8 should always be supported", e);
        }
    }

    @Test
    public void testPrepareErrorResponseForPostBinding() throws Exception {

        String compressedResponse = SAMLSSOUtil.compressResponse(TestConstants.AUTHN_FAILED_SAML_RESPONSE);
        Method method = SAMLSSOProviderServlet.class.getDeclaredMethod("prepareErrorResponseForPostBinding",
                String.class);
        method.setAccessible(true);
        String result = (String) method.invoke(samlssoProviderServlet, compressedResponse);
        assertNotNull(result, "Prepared response should not be null.");
        String decodedResult = new String(java.util.Base64.getDecoder().decode(result));
        assertEquals(decodedResult, TestConstants.AUTHN_FAILED_SAML_RESPONSE,
                "Decoded response should match the original SAML response.");
    }

    @Test
    public void testRemoveTokenIdCookieAppliesProxyContextPath() {

        String tenantDomain = "foo.com";
        Cookie tokenIdCookie = new Cookie("samlssoTokenId",
                "tokenIdValue" + SAMLSSOConstants.TENANT_QUALIFIED_TOKEN_ID_COOKIE_SUFFIX);
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(req.getCookies()).thenReturn(new Cookie[]{tokenIdCookie});

        ServerConfiguration serverConfiguration = mock(ServerConfiguration.class);
        when(serverConfiguration.getFirstProperty(IdentityCoreConstants.PROXY_CONTEXT_PATH)).thenReturn("auth");

        try (MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<ServerConfiguration> serverConfigurationStatic =
                     Mockito.mockStatic(ServerConfiguration.class)) {

            identityUtil.when(() -> IdentityUtil.getIdentityCookieConfig(anyString())).thenReturn(null);
            identityTenantUtil.when(IdentityTenantUtil::isTenantedSessionsEnabled).thenReturn(true);
            identityTenantUtil.when(IdentityTenantUtil::isSuperTenantAppendInCookiePath).thenReturn(false);
            serverConfigurationStatic.when(ServerConfiguration::getInstance).thenReturn(serverConfiguration);

            samlssoProviderServlet.removeTokenIdCookie(req, resp, tenantDomain);
        }

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(resp).addCookie(cookieCaptor.capture());
        assertEquals(cookieCaptor.getValue().getPath(), "/auth/t/" + tenantDomain + "/",
                "The proxy context path is not applied to the tenanted samlssoTokenId cookie path");
    }


    @DataProvider(name = "tokenIdCookiePathDataProvider")
    public Object[][] provideTokenIdCookiePathData() {

        return new Object[][]{
                // loggedInTenantDomain, superTenantAppendInCookiePath, expectedPathPassedToHelper

                // A tenanted cookie path is routed through the proxy context path helper.
                {"foo.com", false, "/t/foo.com/"},

                // When the super tenant is appended, its path is routed through the helper too.
                {"carbon.super", true, "/t/carbon.super/"},
        };
    }

    @Test(dataProvider = "tokenIdCookiePathDataProvider")
    public void testStoreTokenIdCookieAppliesProxyContextPath(String loggedInTenantDomain,
                                                             boolean superTenantAppendInCookiePath,
                                                             String expectedPathPassedToHelper) throws Exception {

        String sessionId = "sessionIdValue" + SAMLSSOConstants.TENANT_QUALIFIED_TOKEN_ID_COOKIE_SUFFIX;
        String prefixedPath = "/auth" + expectedPathPassedToHelper;
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        try (MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class)) {

            identityUtil.when(() -> IdentityUtil.getIdentityCookieConfig(anyString())).thenReturn(null);
            identityTenantUtil.when(IdentityTenantUtil::isTenantedSessionsEnabled).thenReturn(true);
            identityTenantUtil.when(IdentityTenantUtil::isSuperTenantAppendInCookiePath)
                    .thenReturn(superTenantAppendInCookiePath);
            frameworkUtils.when(() -> FrameworkUtils.prependProxyContextPath(expectedPathPassedToHelper))
                    .thenReturn(prefixedPath);

            Method method = SAMLSSOProviderServlet.class.getDeclaredMethod("storeTokenIdCookie",
                    String.class, HttpServletRequest.class, HttpServletResponse.class,
                    String.class, String.class, String.class);
            method.setAccessible(true);
            method.invoke(samlssoProviderServlet, sessionId, req, resp, "foo.com", loggedInTenantDomain,
                    "sessionIdentifier");

            frameworkUtils.verify(() -> FrameworkUtils.prependProxyContextPath(expectedPathPassedToHelper));
        }

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(resp).addCookie(cookieCaptor.capture());
        assertEquals(cookieCaptor.getValue().getPath(), prefixedPath,
                "The samlssoTokenId cookie path should be the value returned by the proxy context path helper");
    }


    @Test
    public void testStoreTokenIdCookieKeepsRootPathForSuperTenant() throws Exception {

        String sessionId = "sessionIdValue" + SAMLSSOConstants.TENANT_QUALIFIED_TOKEN_ID_COOKIE_SUFFIX;
        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        try (MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<IdentityTenantUtil> identityTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class)) {

            identityUtil.when(() -> IdentityUtil.getIdentityCookieConfig(anyString())).thenReturn(null);
            identityTenantUtil.when(IdentityTenantUtil::isTenantedSessionsEnabled).thenReturn(true);
            identityTenantUtil.when(IdentityTenantUtil::isSuperTenantAppendInCookiePath).thenReturn(false);

            Method method = SAMLSSOProviderServlet.class.getDeclaredMethod("storeTokenIdCookie",
                    String.class, HttpServletRequest.class, HttpServletResponse.class,
                    String.class, String.class, String.class);
            method.setAccessible(true);
            method.invoke(samlssoProviderServlet, sessionId, req, resp, "foo.com", "carbon.super",
                    "sessionIdentifier");

            frameworkUtils.verify(() -> FrameworkUtils.prependProxyContextPath(anyString()), never());
        }

        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(resp).addCookie(cookieCaptor.capture());
        assertEquals(cookieCaptor.getValue().getPath(), SAMLSSOConstants.COOKIE_ROOT_PATH,
                "The super tenant cookie path should stay at the root path, which already covers any prefix");
    }

}
