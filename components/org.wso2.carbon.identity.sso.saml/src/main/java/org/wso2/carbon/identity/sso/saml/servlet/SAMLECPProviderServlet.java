package org.wso2.carbon.identity.sso.saml.servlet;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityException;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.model.SamlSSORequestWrapper;
import org.wso2.carbon.identity.sso.saml.util.SAMLSOAPUtils;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.soap.*;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;




public class SAMLECPProviderServlet extends HttpServlet {
    private static Log log = LogFactory.getLog(SAMLECPProviderServlet.class);


    protected void doGet(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse) throws ServletException, IOException {
        try {
            //handleRequest(httpServletRequest, httpServletResponse, false);
            log.warn("Now my ecp servlet works");
        } finally {
            SAMLSSOUtil.removeSaaSApplicationThreaLocal();
            SAMLSSOUtil.removeUserTenantDomainThreaLocal();
            SAMLSSOUtil.removeTenantDomainFromThreadLocal();
            try {
                handleRequest(httpServletRequest, httpServletResponse, true);
            } catch (SOAPException  e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            handleRequest(req, resp, true);

        } catch (SOAPException  e) {
            e.printStackTrace();
            e.getMessage();
        } finally {
            SAMLSSOUtil.removeSaaSApplicationThreaLocal();
            SAMLSSOUtil.removeUserTenantDomainThreaLocal();
            SAMLSSOUtil.removeTenantDomainFromThreadLocal();
        }
    }


    private void handleRequest(HttpServletRequest req, HttpServletResponse resp, boolean isPost)
            throws ServletException, IOException, SOAPException {

        try {
        MessageFactory messageFactory = MessageFactory.newInstance();
        InputStream inStream = req.getInputStream();
        SOAPMessage soapMessage = messageFactory.createMessage(new MimeHeaders(), inStream);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        soapMessage.writeTo(out);
        String strMsg = new String(out.toByteArray());
        log.debug(strMsg);
        log.debug(soapMessage);
        String samlRequest = null;

            samlRequest = SAMLSOAPUtils.decodeSOAPMessage(soapMessage);



        // extract the saml message from the soap request

//        SOAPBody body = soapMessage.getSOAPPart().getEnvelope().getBody();
//        Iterator<?> elements = body.getChildElements();
//        String samlRequest="";
//
//        while (elements.hasNext()) {
//            SOAPElement element = (SOAPElement) elements.next();
//            if(element.getElementName().getPrefix().equals(SAMLSSOConstants.SAML_PROTOCOL) ){
//
//                //if the element is of saml protocol
//                DOMSource source = new DOMSource(element);
//                StringWriter stringResult = new StringWriter();
//                TransformerFactory.newInstance().newTransformer().transform(source, new StreamResult(stringResult));
//                String message = stringResult.toString();
//                samlRequest=Base64.getEncoder().encodeToString(message.getBytes());
//                XMLObject samlobj = SAMLSSOUtil.unmarshall(message);
//
//            }
//        }




        //get the authorization header username and password

        String username="";
        String password="";
        String base64Credentials="";

        final String authorization = req.getHeader("Authorization");

        if (authorization != null && authorization.toLowerCase().startsWith("basic")) {
            // Authorization: Basic base64credentials
            base64Credentials = authorization.substring("Basic".length()).trim();
            byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
            String credentials = new String(credDecoded, StandardCharsets.UTF_8);
            // credentials = username:password
            final String[] values = credentials.split(":", 2);
            username=values[0];
            password=values[1];
            log.warn(username);
            log.warn(password);

        }
        //make a request wrapper to pass the request to the samlsso servlet




        //using the opensaml library


//        XMLObject xmlObject =SAMLSOAPUtils.unmarshall(strMsg);
//        SAMLSOAPUtils.decode(xmlObject);
//        SAMLSOAPUtils.generateSOAPFault();


        if (samlRequest != null) {
            SamlSSORequestWrapper samlSSORequestWrapper = new SamlSSORequestWrapper(req);
            samlSSORequestWrapper.setParameter(SAMLSSOConstants.SAML_REQUEST, samlRequest);
            //samlSSORequestWrapper.setParameter(SAMLSSOConstants.SEC_TOKEN,base64Credentials);
            samlSSORequestWrapper.setParameter("isECP", "true");

            RequestDispatcher dispatcher = req.getRequestDispatcher("/samlsso");
            dispatcher.forward(samlSSORequestWrapper, resp);
        } else {
            log.error("SAML Request is null");
        }

        }catch (Exception e){
            String soapFault = SAMLSOAPUtils.createSOAPFault("An Error Occured");
            log.error(soapFault);
            e.printStackTrace();
            PrintWriter out = resp.getWriter();
            out.print(soapFault);
            resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            resp.setContentType("text/html;charset=UTF-8");


        }
    }
}
