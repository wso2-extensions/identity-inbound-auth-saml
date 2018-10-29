package org.wso2.carbon.identity.sso.saml.util;


import org.testng.annotations.Test;
import org.wso2.carbon.identity.sso.saml.TestConstants;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ECPException;


import static org.testng.Assert.*;

public class SAMLSOAPUtilsTest {

    @Test(expectedExceptions = IdentitySAML2ECPException.class)
    public void testUnmarshallRandomString() throws Exception{
        SAMLSOAPUtils.unmarshall("Random String");
    }

    @Test
    public void testDecodeSOAPMessage() throws Exception {
        String samlRequest = null;
        samlRequest = SAMLSOAPUtils.decodeSOAPMessage(TestUtils.getSOAPBindedSAMLAuthnRequest());
        assertEquals( samlRequest ,TestConstants.SOAP_DECODED_SAML_REQUEST);
    }

    @Test
    public void testCreateSOAPFault() {
        String fault = SAMLSOAPUtils.createSOAPFault("An error Occured","Client");
        assertEquals(fault ,TestConstants.SOAP_FAULT );

    }

    @Test
    public void testCreateSOAPMessage() {
        String soapMessage = SAMLSOAPUtils.createSOAPMessage(TestConstants.AUTHN_SUCCESS_SAML_RESPONSE, "https://localhost/Shibboleth.sso/SAML2/ECP");
        assertEquals(soapMessage, TestConstants.SOAP_MESSAGE );
    }


}