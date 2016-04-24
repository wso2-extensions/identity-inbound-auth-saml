/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import junit.framework.TestCase;

import java.io.IOException;

public class TestSAMLSSOUtil extends TestCase {

    public void setUp() {
    }

    public void testCompressResponse() {
        try {
            String response = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<saml2p:Response Destination=\"https://localhost:9443/samlsso\" " +
                    "ID=\"_bdcada906cfe9ead0580e5941ab50fe5\" IssueInstant=\"2016-04-23T15:25:27.652Z\" Version=\"2" +
                    ".0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer " +
                    "Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\" xmlns:saml2=\"urn:oasis:names:tc" +
                    ":SAML:2.0:assertion\">localhost</saml2:Issuer><saml2p:Status><saml2p:StatusCode " +
                    "Value=\"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed\"/><saml2p:StatusMessage>User " +
                    "authentication failed</saml2p:StatusMessage></saml2p:Status></saml2p:Response>";
            assertFalse("Compressing authentication failed SAML response returned an empty result.", SAMLSSOUtil
                    .compressResponse(response).isEmpty());
        } catch (IOException e) {
            fail("Error while compressing authentication failed SAML response.");
        }
    }

}
