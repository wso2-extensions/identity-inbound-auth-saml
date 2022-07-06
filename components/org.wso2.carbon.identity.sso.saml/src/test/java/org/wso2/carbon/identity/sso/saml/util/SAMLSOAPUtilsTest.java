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
import org.wso2.carbon.identity.sso.saml.SAMLECPConstants;
import org.wso2.carbon.identity.sso.saml.TestConstants;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import static org.testng.Assert.assertEquals;

/**
 * Unit test Cases for SAML SOAP Util.
 */
public class SAMLSOAPUtilsTest {

    @Test
    public void testDecodeSOAPMessage() throws Exception {
        String samlRequest;
        samlRequest = SAMLSOAPUtils.decodeSOAPMessage(TestUtils.getSOAPBindedSAMLAuthnRequest());
        assertEquals(samlRequest, TestConstants.SOAP_DECODED_SAML_REQUEST);
    }

    @Test
    public void testCreateSOAPFault() throws TransformerException, SOAPException {
        String fault = SAMLSOAPUtils.createSOAPFault("An error Occured", SAMLECPConstants.FaultCodes.SOAP_FAULT_CODE_CLIENT);
        assertEquals(fault, TestConstants.SOAP_FAULT);
    }

    @Test
    public void testCreateSOAPMessage() throws TransformerException, SOAPException {
        String soapMessage = SAMLSOAPUtils.createSOAPMessage(TestConstants.AUTHN_SUCCESS_SAML_RESPONSE, TestConstants.SAML_ECP_ACS_URL);
        assertEquals(soapMessage, TestConstants.SOAP_MESSAGE);
    }

    @Test
    public void testConvertSOAPMsgToString() throws Exception {
        SOAPMessage soapMessage = prepareForTestConvertSOAPMsgToString();
        String strMessage = SAMLSOAPUtils.convertSOAPMsgToString(soapMessage).replace
                ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
        assertEquals(strMessage, TestConstants.SOAP_FAULT);
    }

    @Test
    public void testConvertSOAPElementToString() throws Exception {
        SOAPElement element = prepareForTestConvertSOAPElementToString();
        String strelement = SAMLSOAPUtils.convertSOAPElementToString(element);
        assertEquals(strelement, TestConstants.SOAP_FAULT_ELEMENT);
    }

    private SOAPMessage prepareForTestConvertSOAPMsgToString() throws Exception {
        String strsoapMessage = TestConstants.SOAP_FAULT;
        InputStream inputStream = new ByteArrayInputStream(strsoapMessage.replace
                ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "").getBytes(StandardCharsets.UTF_8));
        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage(new MimeHeaders(), inputStream);
        return soapMessage;
    }

    private SOAPElement prepareForTestConvertSOAPElementToString() throws Exception {
        SOAPMessage soapMessage = prepareForTestConvertSOAPMsgToString();
        SOAPBody body = soapMessage.getSOAPPart().getEnvelope().getBody();
        SOAPElement element = null;
        Iterator<?> elements = body.getChildElements();
        while (elements.hasNext()) {
            element = (SOAPElement) elements.next();
        }
        return element;
    }
}
