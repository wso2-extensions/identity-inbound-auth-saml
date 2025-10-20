package org.wso2.carbon.identity.sso.saml.servlet;

import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SAMLSSOProviderServletSendPostRequestTest {

    @DataProvider(name = "tenantFlowScenarios")
    public Object[][] tenantFlowScenarios() {
        return new Object[][]{
                // configEnabled, threadLocalTenant, spTenantDomain, expectedTenantDomain, expectedTenantId
                {true, null, "tenant1.com", "tenant1.com", 12},
                {true, null, null, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID},
                {true, "thread-local-tenant", "tenant1.com", "thread-local-tenant", 12},
                {true, "", "tenant1.com", "tenant1.com", 12},
                {true, "", null, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID},
                {false, null, "tenant1.com", MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID},
                {false, "thread-local-tenant", "tenant1.com", MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, MultitenantConstants.SUPER_TENANT_ID},
        };
    }

    @Test(dataProvider = "tenantFlowScenarios")
    public void testSendPostRequestTenantFlow(boolean configEnabled, String threadLocalTenant,
                                              String spTenantDomain, String expectedTenantDomain,
                                              int expectedTenantId) throws Exception {

        try (MockedStatic<IdentityTenantUtil> idTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<IdentityUtil> identityUtil = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<SAMLSSOUtil> samlssoUtil = Mockito.mockStatic(SAMLSSOUtil.class);
             MockedStatic<PrivilegedCarbonContext> pcc = Mockito.mockStatic(PrivilegedCarbonContext.class);
             MockedConstruction<SignKeyDataHolder> ignored = Mockito.mockConstruction(SignKeyDataHolder.class)) {

            identityUtil.when(() -> IdentityUtil.getProperty(SAMLSSOConstants.SAML_SLO_FRONT_CHANNEL_POST_BINDING_LOGOUT_REQ_SIG_TENANT_CERT))
                    .thenReturn(Boolean.toString(configEnabled));

            idTenantUtil.when(() -> IdentityTenantUtil.getTenantId(anyString())).thenAnswer(invocation -> {
                String domain = invocation.getArgument(0);
                if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(domain)) {
                    return MultitenantConstants.SUPER_TENANT_ID;
                }
                return 12;
            });

            PrivilegedCarbonContext mockContext = mock(PrivilegedCarbonContext.class);
            pcc.when(PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(mockContext);
            pcc.when(PrivilegedCarbonContext::startTenantFlow).thenAnswer(inv -> null);
            pcc.when(PrivilegedCarbonContext::endTenantFlow).thenAnswer(inv -> null);
            doNothing().when(mockContext).setTenantDomain(anyString());
            doNothing().when(mockContext).setTenantId(anyInt());

            // SP DO
            SAMLSSOServiceProviderDO spDO = mock(SAMLSSOServiceProviderDO.class);
            when(spDO.getTenantDomain()).thenReturn(spTenantDomain);
            when(spDO.getSigningAlgorithmUri()).thenReturn("RSA_SHA256");
            when(spDO.getDigestAlgorithmUri()).thenReturn("SHA256");

            LogoutRequest logoutRequest = mock(LogoutRequest.class);
            when(logoutRequest.getDestination()).thenReturn("https://localhost:9443/samlsso");

            samlssoUtil.when(() -> SAMLSSOUtil.setSignature(any(LogoutRequest.class), anyString(), anyString(), any()))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            samlssoUtil.when(SAMLSSOUtil::getTenantDomainFromThreadLocal).thenReturn(threadLocalTenant);

            HttpServletResponse resp = mock(HttpServletResponse.class);
            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);
            when(resp.getWriter()).thenReturn(printWriter);

            // Invoke private sendPostRequest via reflection
            SAMLSSOProviderServlet servlet = new SAMLSSOProviderServlet();
            Method method = SAMLSSOProviderServlet.class.getDeclaredMethod(
                    "sendPostRequest",
                    HttpServletRequest.class,
                    HttpServletResponse.class,
                    SAMLSSOServiceProviderDO.class,
                    LogoutRequest.class
            );
            method.setAccessible(true);
            method.invoke(servlet, mock(HttpServletRequest.class), resp, spDO, logoutRequest);

            if (configEnabled) {
                verify(mockContext, atLeastOnce()).setTenantDomain(expectedTenantDomain);
                verify(mockContext, atLeastOnce()).setTenantId(expectedTenantId);
            } else {
                verify(mockContext, never()).setTenantDomain(anyString());
                verify(mockContext, never()).setTenantId(anyInt());
            }

            String output = stringWriter.toString();
            assert output.contains("samlsso-response-form") || output.length() > 0;
        }
    }
}
