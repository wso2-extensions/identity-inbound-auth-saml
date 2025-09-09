package org.wso2.carbon.identity.sso.saml.servlet;

import org.opensaml.saml.saml2.core.LogoutRequest;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


@PrepareForTest({
        SAMLSSOProviderServlet.class,
        SAMLSSOUtil.class,
        PrivilegedCarbonContext.class,
        IdentityUtil.class,
        IdentityTenantUtil.class,
        SignKeyDataHolder.class
})
public class SAMLSSOProviderServletSendPostRequestTest extends PowerMockTestCase {

    @DataProvider(name = "tenantFlowScenarios")
    public Object[][] tenantFlowScenarios() {
        return new Object[][]{
                // configEnabled, threadLocalTenant, spTenantDomain, expectedTenantDomain, expectedTenantId
                {true, null, "tenant1.com", "tenant1.com", 12},                             // normal tenant
                {true, null, null, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID}, // SP domain null → super tenant
                {true, "thread-local-tenant", "tenant1.com", "thread-local-tenant", 12},    // thread-local overrides SP
                {true, "", "tenant1.com", "tenant1.com", 12},                               // empty thread-local → SP domain
                {true, "", null, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID}, // empty thread-local + SP null → super tenant
                {false, null, "tenant1.com", MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID}, // config disabled → always super tenant
                {false, "thread-local-tenant", "tenant1.com", MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID}, // config disabled, thread-local ignored
        };
    }

    @Test(dataProvider = "tenantFlowScenarios")
    public void testSendPostRequestTenantFlow(boolean configEnabled, String threadLocalTenant,
                                              String spTenantDomain, String expectedTenantDomain,
                                              int expectedTenantId) throws Exception {

        // --- Mock static methods ---
        PowerMockito.mockStatic(IdentityTenantUtil.class);
        PowerMockito.mockStatic(IdentityUtil.class);
        PowerMockito.mockStatic(SAMLSSOUtil.class);
        PowerMockito.mockStatic(PrivilegedCarbonContext.class);

        // --- Mock IdentityUtil property ---
        when(IdentityUtil.getProperty(SAMLSSOConstants.SAML_SLO_FRONT_CHANNEL_POST_BINDING_LOGOUT_REQ_SIG_TENANT_CERT))
                .thenReturn(Boolean.toString(configEnabled));

        // --- Mock tenant ID resolution ---
        when(IdentityTenantUtil.getTenantId(anyString())).thenAnswer(invocation -> {
            String domain = invocation.getArgument(0);
            if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(domain)) {
                return MultitenantConstants.SUPER_TENANT_ID;
            }
            return 12; // dummy tenant ID for other tenants
        });

        // --- Mock CarbonContext ---
        PrivilegedCarbonContext mockContext = mock(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(mockContext);
        PowerMockito.doNothing().when(PrivilegedCarbonContext.class, "startTenantFlow");
        PowerMockito.doNothing().when(PrivilegedCarbonContext.class, "endTenantFlow");
        doNothing().when(mockContext).setTenantDomain(anyString());
        doNothing().when(mockContext).setTenantId(anyInt());

        // --- Mock ServiceProviderDO ---
        SAMLSSOServiceProviderDO spDO = mock(SAMLSSOServiceProviderDO.class);
        when(spDO.getTenantDomain()).thenReturn(spTenantDomain);
        when(spDO.getSigningAlgorithmUri()).thenReturn("RSA_SHA256");
        when(spDO.getDigestAlgorithmUri()).thenReturn("SHA256");

        // --- Mock LogoutRequest ---
        LogoutRequest logoutRequest = mock(LogoutRequest.class);
        when(logoutRequest.getDestination()).thenReturn("https://localhost:9443/samlsso");

        // --- Mock SignKeyDataHolder to avoid real keystore access ---
        SignKeyDataHolder mockCredential = mock(SignKeyDataHolder.class);
        PowerMockito.whenNew(SignKeyDataHolder.class).withAnyArguments().thenReturn(mockCredential);

        // --- Mock SAMLSSOUtil.setSignature to return input LogoutRequest ---
        PowerMockito.when(SAMLSSOUtil.setSignature(any(LogoutRequest.class), anyString(), anyString(), any()))
                .thenAnswer(invocation -> invocation.getArgument(0));

        // --- Mock thread-local tenant domain if provided ---
        when(SAMLSSOUtil.getTenantDomainFromThreadLocal()).thenReturn(threadLocalTenant);

        // --- Mock HttpServletResponse with PrintWriter ---
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);
        when(resp.getWriter()).thenReturn(printWriter);

        // --- Spy servlet to mock resolveAppName ---
        SAMLSSOProviderServlet spyServlet = PowerMockito.spy(new SAMLSSOProviderServlet());
        PowerMockito.doReturn("TestSP").when(spyServlet, "resolveAppName");

        // --- Invoke private sendPostRequest using reflection ---
        Method method = SAMLSSOProviderServlet.class.getDeclaredMethod(
                "sendPostRequest",
                HttpServletRequest.class,
                HttpServletResponse.class,
                SAMLSSOServiceProviderDO.class,
                LogoutRequest.class
        );
        method.setAccessible(true);
        method.invoke(spyServlet, mock(HttpServletRequest.class), resp, spDO, logoutRequest);

        // --- Verify tenant domain and ID set correctly ---
        if (configEnabled) {
            verify(mockContext, atLeastOnce()).setTenantDomain(expectedTenantDomain);
            verify(mockContext, atLeastOnce()).setTenantId(expectedTenantId);
        } else {
            // Config disabled → tenant flow skipped, default super tenant used
            verify(mockContext, never()).setTenantDomain(anyString());
            verify(mockContext, never()).setTenantId(anyInt());
        }

        // --- Verify output generated ---
        String output = stringWriter.toString();
        assert output.contains("TestSP");
    }
}
