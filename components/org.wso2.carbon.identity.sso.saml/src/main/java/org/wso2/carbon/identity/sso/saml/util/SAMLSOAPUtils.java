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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.sso.saml.SAMLECPConstants;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ECPException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Base64;
import java.util.Iterator;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;


/**
 * A Utility which provides functionality to handle SOAP requests and responses.
 */
public class SAMLSOAPUtils {

    private static Log log = LogFactory.getLog(SAMLSOAPUtils.class);

    /**
     *
     * Decode the request received by the samlecp servlet.
     * Validate the SOAP message
     * Check whether the SOAP body contains a valid SAML request
     * @param soapMessage
     * @return
     * @throws IdentitySAML2ECPException
     */
    public static String decodeSOAPMessage(SOAPMessage soapMessage) throws IdentitySAML2ECPException,
            TransformerException {
        SOAPBody body;
        String samlRequest = null;
        String strElement;
        if (soapMessage != null) {
            try {
                body = soapMessage.getSOAPPart().getEnvelope().getBody();
            } catch (SOAPException e) {
                String err = "Invalid SOAP Request";
                throw new IdentitySAML2ECPException(err, e);
            }
            int elementSize = 0;
            Iterator<?> elements = body.getChildElements();
            while (elements.hasNext()) {
                SOAPElement element = (SOAPElement) elements.next();
                strElement = convertSOAPElementToString(element);
                samlRequest = Base64.getEncoder().encodeToString(strElement.getBytes());
                elementSize += 1;
            }
            if (elementSize == 0) {
                String err = "SOAP message body cannot be Null";
                throw new IdentitySAML2ECPException(err);
            } else if (elementSize > 1) {
                String err = "SOAP Message body should Only contain a valid SAML Request";
                throw new IdentitySAML2ECPException(err);
            }
        } else {
            String err = "Empty SOAP Request";
            throw new IdentitySAML2ECPException(err);
        }
        return samlRequest;
    }

    /**
     *
     * Creates a SOAP Fault message including the fault code and fault string.
     * @param faultString detailed error message
     * @param faultcode
     * @return
     */
    public static String createSOAPFault(String faultString, String faultcode) throws TransformerException,
            SOAPException {
        SOAPMessage soapMsg;
        MessageFactory factory = MessageFactory.newInstance();
        soapMsg = factory.createMessage();
        SOAPPart part = soapMsg.getSOAPPart();
        SOAPEnvelope envelope = part.getEnvelope();
        SOAPBody body = envelope.getBody();
        SOAPFault fault = body.addFault();
        fault.setFaultString(faultString);
        fault.setFaultCode(new QName(SAMLECPConstants.SOAPNamespaceURI.SOAP_NAMESPACE_URI, faultcode));
        return convertSOAPMsgToString(soapMsg).replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
    }

    /**
     *
     * @param samlRes SAML Response
     * @param acUrl Assertion Consumer URL
     * @return
     */
    public static String createSOAPMessage(String samlRes, String acUrl) throws TransformerException, SOAPException {
        SOAPMessage soapMsg;
        MessageFactory factory = MessageFactory.newInstance();
        soapMsg = factory.createMessage();
        SOAPPart part = soapMsg.getSOAPPart();
        SOAPEnvelope envelope = part.getEnvelope();
        SOAPHeader header = envelope.getHeader();
        SOAPHeaderElement soapHeaderElement = header.addHeaderElement(envelope.createName(
                SAMLECPConstants.SOAPECPHeaderElements.SOAP_ECP_HEADER_LOCAL_NAME,
                SAMLECPConstants.SOAPECPHeaderElements.SOAP_ECP_HEADER_PREFIX,
                SAMLECPConstants.SOAPECPHeaderElements.SOAP_ECP_HEADER_URI));
        soapHeaderElement.setMustUnderstand(true);
        soapHeaderElement.setActor(SAMLECPConstants.SOAPHeaderElements.SOAP_HEADER_ELEMENT_ACTOR);
        soapHeaderElement.addAttribute(new QName(SAMLECPConstants.SOAPHeaderElements.SOAP_HEADER_ELEMENT_ACS_URL),
                acUrl);
        SOAPBody body = envelope.getBody();
        String rawxml = "<![CDATA[" + samlRes + "]]>";
        body.addTextNode(rawxml);
        return convertSOAPMsgToString(soapMsg).replace("<![CDATA[", "").replace("]]>", "");
    }

    /**
     *Converts a  SOAP Message to String.
     * @param soapMessage
     * @return
     */
    public static String convertSOAPMsgToString(SOAPMessage soapMessage) throws TransformerException {
        String strElement;
        final StringWriter stringWriter = new StringWriter();
        TransformerFactory.newInstance().newTransformer().transform(
                new DOMSource(soapMessage.getSOAPPart()), new StreamResult(stringWriter));
        strElement = stringWriter.toString();
        return strElement;
    }

    /**
     *Send the SOAP fault with the servlet response.
     * @param resp Servlet response
     * @param faultsring SOAP Fault code
     * @param faultcode SOAP fault code
     */
    public static void sendSOAPFault(HttpServletResponse resp, String faultsring, String faultcode) {
        PrintWriter out = null;
        String soapFault = null;
        try {
            out = resp.getWriter();
            soapFault = SAMLSOAPUtils.createSOAPFault(faultsring, faultcode);
        } catch (SOAPException | TransformerException | IOException e) {
            String message = "Error Generating the SOAP Fault";
            log.error(message, e);
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.setContentType("text/html;charset=UTF-8");
        }
        log.error(soapFault);
        resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        resp.setContentType("text/html;charset=UTF-8");
        if (out != null) {
            out.print(soapFault);
        }
    }

    /**
     * Converts SOAPElement to String.
     * @param element SOAPElement
     * @return
     * @throws TransformerException
     */
    public static String convertSOAPElementToString(SOAPElement element) throws TransformerException {
        String strElement;
        StringWriter stringWriter = new StringWriter();
        TransformerFactory.newInstance().newTransformer().transform(
                new DOMSource(element), new StreamResult(stringWriter));
        strElement = stringWriter.toString().replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
        return strElement;
    }
}
