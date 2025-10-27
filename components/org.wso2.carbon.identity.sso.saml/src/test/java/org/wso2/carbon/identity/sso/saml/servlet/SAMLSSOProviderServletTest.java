package org.wso2.carbon.identity.sso.saml.servlet;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOSessionDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
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
}
