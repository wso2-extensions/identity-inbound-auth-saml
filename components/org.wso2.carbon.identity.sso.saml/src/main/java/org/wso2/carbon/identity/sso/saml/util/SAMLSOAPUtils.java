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
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ECPException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
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
    private static boolean isBootStrapped = false;
    public static final String SOAP_FAULT_CODE_CLIENT = "Client";
    public static final String SAOP_FAULT_CODE_SERVER = "Server";

    /**
     *
     * @param authReqStr Authentication Request
     * @return
     * @throws IdentityException
     * @throws IdentitySAML2ECPException
     */
    public static XMLObject unmarshall(String authReqStr) throws IdentityException, IdentitySAML2ECPException {
        InputStream inputStream = null;
        doBootstrap();
        try {
            DocumentBuilderFactory documentBuilderFactory = IdentityUtil.getSecuredDocumentBuilderFactory();
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            inputStream = new ByteArrayInputStream(authReqStr.trim().getBytes(StandardCharsets.UTF_8));
            Document document = docBuilder.parse(inputStream);
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            String err = "Error in Processing the  SAML request";
            throw new IdentitySAML2ECPException(err);
        }
    }

    /**
     *
     * Decode the request recived by the /ecp servlet.
     * Validate the SOAP message
     * Check whether the SOAP body contains a valid SAML request
     * @param soapMessage
     * @return
     * @throws IdentitySAML2ECPException
     */
    public static String decodeSOAPMessage(SOAPMessage soapMessage) throws IdentitySAML2ECPException {
        SOAPBody body = null;
        String samlRequest = null;
        String message = null;
        try {
            body = soapMessage.getSOAPPart().getEnvelope().getBody();
        } catch (SOAPException e) {
            log.error("Error Processing the SOAP Mesage");
            throw new IdentitySAML2ECPException(e.getMessage());
        }
        int elementSize = 0;
        try {
            Iterator<?> elements = body.getChildElements();
            while (elements.hasNext()) {
                SOAPElement element = (SOAPElement) elements.next();
                DOMSource source = new DOMSource(element);
                StringWriter stringResult = new StringWriter();
                try {
                    TransformerFactory.newInstance().newTransformer().transform(source, new StreamResult(stringResult));
                } catch (TransformerException e) {
                    String err = "Transformer Exception";
                    log.error(err);
                    throw new IdentitySAML2ECPException(e.getMessage());
                }
                message = stringResult.toString().replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
                samlRequest = Base64.getEncoder().encodeToString(message.getBytes());
                elementSize += 1;
            }
        } catch (NullPointerException e) {
            String err = "SOAP message body cannot be null";
            log.error(err);
            throw new IdentitySAML2ECPException(e.getMessage());
        }
        if (elementSize == 0) {
            String err = "The SOAP message body is Empty";
            log.error(err);
            throw new IdentitySAML2ECPException(err);
        } else if (elementSize == 1) {
            try {
                unmarshall(message);
            } catch (IdentityException e) {
                String err =  "SOAP Message doesn't contain a valid SAML Request";
                log.warn(err);
                throw new IdentitySAML2ECPException(err);
            }
        } else if (elementSize > 1) {
            String err = "SOAP Message contains more than one XML Element";
            log.error(err);
            throw new IdentitySAML2ECPException(err);
        }
        return samlRequest;
    }

    /**
     *
     * Creates a SOAP Fault message including the fault coe and fault string.
     * @param faultString detailed error message
     * @param faultcode
     * @return
     */
    public static String createSOAPFault(String faultString, String faultcode) {
        SOAPMessage soapMsg =  null;
        try {
            MessageFactory factory = MessageFactory.newInstance();
            soapMsg = factory.createMessage();
            SOAPPart part = soapMsg.getSOAPPart();
            SOAPEnvelope envelope = part.getEnvelope();
            SOAPBody body = envelope.getBody();
            SOAPFault fault = body.addFault();
            fault.setFaultString(faultString);
            fault.setFaultCode(new QName("http://schemas.xmlsoap.org/soap/envelope/", faultcode));

        } catch (SOAPException e) {
            String err = "SOAP Exception when creating SOAP fault";
            log.error(err);
        }
        if (soapMsg != null) {
            return convertSOAPToString(soapMsg).replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");
        } else {
            return null;
        }
    }

    /**
     *
     * @param samlRes
     * @param acUrl
     * @return
     */
    public static String createSOAPMessage(String samlRes, String acUrl) {
        SOAPMessage soapMsg = null;
        try {
            MessageFactory factory = MessageFactory.newInstance();
            soapMsg = factory.createMessage();
            SOAPPart part = soapMsg.getSOAPPart();
            SOAPEnvelope envelope = part.getEnvelope();
            SOAPHeader header = envelope.getHeader();
            SOAPHeaderElement soapHeaderElement = header.addHeaderElement(envelope.createName("Response",
                    "ecp",
                    "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"));
            soapHeaderElement.setMustUnderstand(true);
            soapHeaderElement.setActor("http://schemas.xmlsoap.org/soap/actor/next");
            soapHeaderElement.addAttribute(new QName("AssertionConsumerServiceURL"),
                    acUrl);
            SOAPBody body = envelope.getBody();
            String rawxml = "<![CDATA[" + samlRes + "]]>";
            body.addTextNode(rawxml);
        } catch (SOAPException e) {
            log.error("SOAP Exception when creating SOAP Response");
        }
        if (soapMsg != null) {
            return convertSOAPToString(soapMsg).replace("<![CDATA[", "").replace("]]>", "");
        } else {
            return null;
        }
    }

    /**
     *Converts a  SOAP Message to String.
     * @param soapMessage
     * @return
     */
    public static String convertSOAPToString(SOAPMessage soapMessage) {
        final StringWriter stringWriter = new StringWriter();
        try {
            TransformerFactory.newInstance().newTransformer().transform(
                    new DOMSource(soapMessage.getSOAPPart()),
                    new StreamResult(stringWriter));
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        }
        return stringWriter.toString();
    }

    /**
     *Send the SOAP fault with the servlet response.
     * @param resp Servlet response
     * @param faultsring SOAP Fault code
     * @param faultcode SOAP fault code
     */
    public static void sendSOAPFault(HttpServletResponse resp, String faultsring , String faultcode) {
        PrintWriter out = null;
        try {
            out = resp.getWriter();
        } catch (IOException e) {
            log.error("An IO Exception Occured ");
        }
        String soapFault = SAMLSOAPUtils.createSOAPFault(faultsring, faultcode);
        log.error(soapFault);
        resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        resp.setContentType("text/html;charset=UTF-8");
        out.print(soapFault);
    }

    public static void doBootstrap() {
        if (!isBootStrapped) {
            try {
                DefaultBootstrap.bootstrap();
                isBootStrapped = true;
            } catch (ConfigurationException e) {
                log.error("Error in bootstrapping the OpenSAML2 library", e);
            }
        }
    }
}
