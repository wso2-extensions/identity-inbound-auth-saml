/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.opensaml.core.xml.XMLObject;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.TestConstants;

import static org.testng.Assert.assertEquals;

/**
 * Unit test cases for SAMLSSOUtil Marshall and UnMarshall.
 */
public class SAMLSSOUtilMarshallTest {

    @Test
    public void testUnmarshall() throws Exception {

        XMLObject xmlObject = SAMLSSOUtil.unmarshall(TestConstants.DECODED_POST_LOGOUT_REQUEST);
        assertEquals(xmlObject.getDOM().getAttributeNode("Destination").getValue(),
                "https://localhost:9443/samlsso",
                "Destination node value of unmarshalled Post Authentication Request is as not expected.");
        assertEquals(xmlObject.getDOM().getAttributeNode("Reason").getValue(), "Single Logout",
                "Reason node value of unmarshalled Post Authentication Request is as not expected.");
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testUnMarshallRandomString() throws Exception {

        XMLObject xmlObject = SAMLSSOUtil.unmarshall("Random String");
    }

    @Test
    public void testMarshall() throws Exception {

        assertEquals(SAMLSSOUtil.marshall(SAMLSSOUtil.unmarshall(TestConstants.DECODED_POST_LOGOUT_REQUEST)),
                TestConstants.DECODED_POST_LOGOUT_REQUEST,
                "Marshaled Post Authentication Request is not as expected.");
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testMarshallNonXML() throws Exception {

        SAMLSSOUtil.marshall(null);
    }
}
