package org.wso2.carbon.identity.sso.saml.util;

import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ECPException;
import org.xml.sax.InputSource;
import org.apache.axis2.transport.http.ServletBasedOutTransportInfo;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.saml.SAMLUtil;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.ecp.Response;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.common.SOAPObject;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.*;
import org.opensaml.ws.soap.soap11.decoder.SOAP11Decoder;
import org.opensaml.ws.soap.soap11.impl.FaultBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.soap.*;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class SAMLSOAPUtils {


    private static Log log = LogFactory.getLog(SAMLSOAPUtils.class);

    public static XMLObject unmarshall(String authReqStr) throws IdentityException {
        InputStream inputStream = null;
        try {
            DocumentBuilderFactory documentBuilderFactory = IdentityUtil.getSecuredDocumentBuilderFactory();
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            inputStream = new ByteArrayInputStream(authReqStr.trim().getBytes(StandardCharsets.UTF_8));
            Document document = docBuilder.parse(inputStream);
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (Exception e) {
            log.error("Error in Processing the  SAML request", e);
            throw IdentityException.error(
                    "Error in Processing the SAML request ",
                    e);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    log.error("Error while closing the stream", e);
                }
            }
        }
    }



    public static void decode(XMLObject soapObject) {
        if (soapObject instanceof Envelope) {
            Envelope envelope = (Envelope) soapObject;
            Body body = envelope.getBody();
//
//           log.warn(Envelope.DEFAULT_ELEMENT_NAME.getNamespaceURI());
//           log.warn(envelope.getElementQName().getNamespaceURI());
//
//           log.warn(Envelope.DEFAULT_ELEMENT_NAME.getLocalPart());
//           log.warn(envelope.getElementQName().getLocalPart());
//
//           log.warn(Envelope.DEFAULT_ELEMENT_NAME.getPrefix());
//           log.warn(envelope.getElementQName().getPrefix());

            if (Envelope.DEFAULT_ELEMENT_NAME.getNamespaceURI() != envelope.getElementQName().getNamespaceURI()) {
                log.error("Name spaces error");

            }
            Header header = envelope.getHeader();

            if (body.getUnknownXMLObjects().isEmpty()) {
                log.error("The SOAP message body is EMPTY");
            } else if (body.getUnknownXMLObjects().size() == 1) {
                XMLObject soapbodyObject = body.getUnknownXMLObjects().get(0);
                if (soapbodyObject != null && soapbodyObject instanceof AuthnRequest) {
                    log.debug("SOAP message SAML Authentication Request");

                } else {
                    log.error("SOAP message doesn't contain any SAML Request");
                }

            } else {
                log.error("The SOAP message must not contain more than one element");
            }

        } else {
            log.error("SOAP error");
        }

    }



    public static String decodeSOAPMessage(SOAPMessage soapMessage) throws IdentitySAML2ECPException {
        SOAPBody body = null;
        String samlRequest = null;
        String message = null;
        try {
            body = soapMessage.getSOAPPart().getEnvelope().getBody();
        } catch (SOAPException e) {
            log.error("Error Processing the SOAP Mesage");
            e.printStackTrace();
            throw new IdentitySAML2ECPException(e.getMessage());
        }

        int ElementSize = 0;
        try {
            Iterator<?> elements = body.getChildElements();
            while (elements.hasNext()) {
                SOAPElement element = (SOAPElement) elements.next();
                DOMSource source = new DOMSource(element);
                StringWriter stringResult = new StringWriter();
                try {
                    TransformerFactory.newInstance().newTransformer().transform(source, new StreamResult(stringResult));
                } catch (TransformerException e) {
                    e.printStackTrace();
                }
                message = stringResult.toString();
                samlRequest = Base64.getEncoder().encodeToString(message.getBytes());
                ElementSize += 1;
            }
        } catch (NullPointerException e) {
            String err = "SOAP message body cannot be null";
            log.error(err);
            e.printStackTrace();
            throw new IdentitySAML2ECPException(e.getMessage());
        }
        if (ElementSize == 0) {
            String err = "The SOAP message body is EMPTY";
            log.error(err);
            throw new IdentitySAML2ECPException(err);
        } else if (ElementSize == 1) {
            try {
                unmarshall(message);
                String err = "The  Received SOAP Request Contains a SAML Request";
                log.debug(err);
            } catch (IdentityException e) {
                String err =  "SOAP Message doesn't contain a valid SAML Request";
                e.printStackTrace();
                log.warn(err);
                throw new IdentitySAML2ECPException(err);
            }
        } else if(ElementSize > 1){
            String err = "SOAP Message contains more than one XML Element";
            log.error(err);
            throw new IdentitySAML2ECPException(err);
        }
        return samlRequest;
    }

    public static Envelope generateSOAPFault() throws IdentityException {

//        XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();
//
//        SOAPObjectBuilder<Envelope> envelopeSOAPObjectBuilder = (SOAPObjectBuilder<Envelope>) builderFactory.getBuilder(
//                Envelope.DEFAULT_ELEMENT_NAME);
//        Envelope envelope = envelopeSOAPObjectBuilder.buildObject();
//
//        SOAPObjectBuilder<Fault> faultSOAPObjectBuilder = (SOAPObjectBuilder<Fault>) builderFactory.getBuilder(
//                Fault.DEFAULT_ELEMENT_NAME);
//        Fault fault = faultSOAPObjectBuilder.buildObject();
//
//        SOAPObjectBuilder<FaultCode> faultCodeSOAPObjectBuilder = (SOAPObjectBuilder<FaultCode>) builderFactory.getBuilder(
//                FaultCode.DEFAULT_ELEMENT_NAME);
//        FaultCode faultCode = faultCodeSOAPObjectBuilder.buildObject();
//
//        SOAPObjectBuilder<FaultString> faultStringSOAPObjectBuilder = (SOAPObjectBuilder<FaultString>) builderFactory.getBuilder(
//                FaultString.DEFAULT_ELEMENT_NAME);
//        FaultString faultString = faultStringSOAPObjectBuilder.buildObject();
//
//        SOAPObjectBuilder<Body> bodySOAPObjectBuilder = (SOAPObjectBuilder<Body>) builderFactory.getBuilder(
//                Body.DEFAULT_ELEMENT_NAME);
//        Body body = bodySOAPObjectBuilder.buildObject();
//
//        faultCode.setValue(FaultCode.CLIENT);
//        faultString.setValue(FaultString.DEFAULT_ELEMENT_LOCAL_NAME);
//        fault.setCode(faultCode);
//        fault.setMessage(faultString);
//
//        body.getUnknownXMLObjects().add(fault);
//        envelope.setBody(body);
//        System.out.println(envelope.getDOM());



        XMLObjectBuilderFactory bf = Configuration.getBuilderFactory();
        Envelope envelope = (Envelope) bf.getBuilder(Envelope.DEFAULT_ELEMENT_NAME).buildObject(Envelope.DEFAULT_ELEMENT_NAME);
        Body body = (Body) bf.getBuilder(Body.DEFAULT_ELEMENT_NAME).buildObject(Body.DEFAULT_ELEMENT_NAME);
        Fault fault = (Fault) bf.getBuilder(Fault.DEFAULT_ELEMENT_NAME).buildObject(Fault.DEFAULT_ELEMENT_NAME);

        FaultCode faultCode = (FaultCode) bf.getBuilder(FaultCode.DEFAULT_ELEMENT_NAME).buildObject(FaultString.DEFAULT_ELEMENT_NAME);
        //faultCode.setValue(FaultActor.DEFAULT_ELEMENT_NAME)
        faultCode.setValue(new QName("faultactor"));

        FaultString faultString = (FaultString) bf.getBuilder(FaultString.DEFAULT_ELEMENT_NAME).buildObject(FaultString.DEFAULT_ELEMENT_NAME);
        faultString.setValue("This is my fault string value");

        //FaultActor faultActor = (FaultActor) bf.getBuilder(FaultActor.DEFAULT_ELEMENT_NAME).buildObject(Envelope.DEFAULT_ELEMENT_NAME);
        //faultActor.setValue(FaultActor.DEFAULT_ELEMENT_LOCAL_NAME);
        fault.setMessage(faultString);
        fault.setCode(faultCode);
        //fault.setActor(faultActor);
        body.getUnknownXMLObjects().add(fault);
        envelope.setBody(body);
        System.out.println(XMLHelper.prettyPrintXML(marshallObject(envelope)));
        //System.out.println(XMLHelper.prettyPrintXML(envelope.getDOM()));


        return envelope;
    }





    public static Element marshallObject(XMLObject object) {
        if (object.getDOM() == null) {
            Marshaller m = Configuration.getMarshallerFactory().getMarshaller(object);
            if (m == null) {
                throw new IllegalArgumentException("No unmarshaller for " + object);
            }
            try {
                return m.marshall(object);
            } catch (MarshallingException e) {
                System.out.println("Marshalling Exception");
            }
        } else {
            return object.getDOM();
        }
        return null;
    }

    public static String createSOAPFault(String faultString){
        SOAPMessage soapMsg =  null;
        try {
            MessageFactory factory = MessageFactory.newInstance();
            soapMsg = factory.createMessage();
            SOAPPart part = soapMsg.getSOAPPart();

            SOAPEnvelope envelope = part.getEnvelope();
            SOAPHeader header = envelope.getHeader();
            SOAPBody body = envelope.getBody();
            SOAPFault fault = body.addFault();
            fault.setFaultString(faultString);

        } catch (SOAPException e){
            log.error("SOAP Exception when creating SOAP fault");
        }
        return soapMessageToString(soapMsg);
    }

    public static String createSOAPMessage(String samlRes, String acUrl){
        SOAPMessage soapMsg =  null;

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
           // soapHeaderElement.setValue("AssertionConsumerServiceURL=\"" +acUrl+"\"");
            soapHeaderElement.addAttribute(new QName("AssertionConsumerServiceURL"),
                    acUrl);
            //soapHeaderElement.addTextNode("AssertionConsumerServiceURL=\"" +acUrl+"\"");
            //soapHeaderElement.addChildElement("AssertionConsumerServiceURL=\"" +acUrl+"\"");
            SOAPBody body = envelope.getBody();
            //body.addDocument(convertStringToDocument(samlRes));
            String rawxml = "<![CDATA["+samlRes+"]]>";
            //rawxml = rawxml.replace("<![CDATA[","").replace("]]","");

             body.addTextNode(rawxml);
            //body.addDocument(convertStringToDocument(samlRes));


        } catch (SOAPException e){
            log.error("SOAP Exception when creating SOAP Response");

        }
        return convertSOAPToString(soapMsg).replace("<![CDATA[","").replace("]]>","");

    }

    public static  String createSOAPECPHeader(String acUrl){
        return "AssertionConsumerServiceURL=\""+acUrl+"\" soap11:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" soap11:mustUnderstand=\"1\" ";
    }


    public static String soapMessageToString(SOAPMessage message)
    {
        String result = null;

        if (message != null)
        {
            ByteArrayOutputStream baos = null;
            try
            {
                baos = new ByteArrayOutputStream();
                message.writeTo(baos);
                result = baos.toString();
            }
            catch (Exception e)
            {
            }
            finally
            {
                if (baos != null)
                {
                    try
                    {
                        baos.close();
                    }
                    catch (IOException ioe)
                    {
                    }
                }
            }
        }
        return result;
    }

    public static String convertSOAPToString(SOAPMessage soapMessage){
        final StringWriter sw = new StringWriter();
        try {
            TransformerFactory.newInstance().newTransformer().transform(
                    new DOMSource(soapMessage.getSOAPPart()),
                    new StreamResult(sw));
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        }
        System.out.println(sw.toString());
        return sw.toString();

    }


    private static Document convertStringToDocument(String xmlStr) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder;
        try {
            builder = factory.newDocumentBuilder();
            Document doc = builder.parse(String.valueOf(new InputSource(new StringReader(xmlStr))));
            //Document doc = builder.parse(new ByteArrayInputStream(xmlStr.trim().getBytes(StandardCharsets.UTF_8)));
            return doc;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }






}


