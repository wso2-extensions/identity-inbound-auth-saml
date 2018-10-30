/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml.util;


import org.testng.annotations.Test;
import org.wso2.carbon.identity.sso.saml.TestConstants;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ECPException;

import static org.testng.Assert.assertEquals;


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
        String soapMessage = SAMLSOAPUtils.createSOAPMessage(TestConstants.AUTHN_SUCCESS_SAML_RESPONSE, TestConstants.SAML_ECP_ACS_URL);
        assertEquals(soapMessage, TestConstants.SOAP_MESSAGE );
    }


}