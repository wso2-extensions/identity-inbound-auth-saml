package org.wso2.carbon.identity.sso.saml.servlet;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.List;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;

@PrepareForTest({SAMLSSOUtil.class})
public class SAMLSSOProviderServletTest extends PowerMockTestCase {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private SAMLSSOAuthnReqDTO authnReqDTO;

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
}
