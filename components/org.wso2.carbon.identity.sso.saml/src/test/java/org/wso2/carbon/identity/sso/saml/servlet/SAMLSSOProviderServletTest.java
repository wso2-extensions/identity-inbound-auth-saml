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
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
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

    @Test(dataProvider = "testValidateDestination")
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

    @Test
    public void testDoubleEncodingDisabled() throws Exception {

        String artifact = "artifact+plus";
        String relayState = "relay state";

        try (MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class)) {

            identityUtil.when(() -> IdentityUtil.getProperty(
                    IdentityConstants.ServerConfig.SAML2_ARTIFACT_DOUBLE_ENCODING_DISABLED))
                    .thenReturn("true");
            frameworkUtils.when(() -> FrameworkUtils.appendQueryParamsToUrl(anyString(), anyMap()))
                    .thenAnswer(invocation -> {
                        @SuppressWarnings("unchecked")
                        java.util.Map<String, String> params = invocation.getArgument(1);
                        assertEquals(params.get(SAMLSSOConstants.SAML_ART), artifact);
                        assertEquals(params.get(SAMLSSOConstants.RELAY_STATE),
                                URLEncoder.encode(relayState, StandardCharsets.UTF_8.name()));
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

    @Test
    public void testDoubleEncodingEnabled() throws Exception {

        String artifact = "artifact+plus";
        String relayState = "relay state";
        String encodedArtifact = URLEncoder.encode(artifact, StandardCharsets.UTF_8.name());
        String encodedRelayState = URLEncoder.encode(relayState, StandardCharsets.UTF_8.name());

        try (MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<FrameworkUtils> frameworkUtils = Mockito.mockStatic(FrameworkUtils.class)) {

            identityUtil.when(() -> IdentityUtil.getProperty(
                    IdentityConstants.ServerConfig.SAML2_ARTIFACT_DOUBLE_ENCODING_DISABLED))
                    .thenReturn("false");
            frameworkUtils.when(() -> FrameworkUtils.appendQueryParamsToUrl(anyString(), anyMap()))
                    .thenAnswer(invocation -> {
                        @SuppressWarnings("unchecked")
                        java.util.Map<String, String> params = invocation.getArgument(1);
                        assertEquals(params.get(SAMLSSOConstants.SAML_ART), encodedArtifact);
                        assertEquals(params.get(SAMLSSOConstants.RELAY_STATE), encodedRelayState);
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
}
