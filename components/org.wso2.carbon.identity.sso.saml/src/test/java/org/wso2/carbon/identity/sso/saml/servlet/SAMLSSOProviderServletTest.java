package org.wso2.carbon.identity.sso.saml.servlet;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOSessionDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.powermock.reflect.Whitebox;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

@PrepareForTest({SAMLSSOUtil.class})
public class SAMLSSOProviderServletTest extends PowerMockTestCase {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private SAMLSSOAuthnReqDTO authnReqDTO;

    @Mock
    private SAMLSSOProviderServlet samlssoProviderServlet;

    @Mock
    private SAMLSSOSessionDTO samlssoSessionDTO;

    @Mock
    private SAMLSSOAuthnReqDTO samlssoAuthnReqDTO;

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

        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.getDestinationFromTenantDomain(anyString())).thenReturn(idpDestinationUrls);
        when(authnReqDTO.getDestination()).thenReturn(providedDestinationUrl);

        SAMLSSOProviderServlet servlet = new SAMLSSOProviderServlet();
        boolean isValid = servlet.isDestinationUrlValid(authnReqDTO, request, response);

        assertEquals(isValid, expected);
    }

    @Test
    public void testNullAuthenticationResult() throws Exception {

        try {
            Whitebox.invokeMethod(samlssoProviderServlet, "populateAuthenticationContextClassRefResult",
                    (AuthenticationResult) null, samlssoSessionDTO, samlssoAuthnReqDTO);
        } catch (NullPointerException e) {
            fail("Authentication Result can be null. Check for null value should be added to avoid Null pointer " +
                    "exceptions.");
        }
    }
}
