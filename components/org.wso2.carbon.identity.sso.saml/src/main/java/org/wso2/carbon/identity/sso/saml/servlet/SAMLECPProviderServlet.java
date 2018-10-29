package org.wso2.carbon.identity.sso.saml.servlet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ECPException;
import org.wso2.carbon.identity.sso.saml.model.SamlSSORequestWrapper;
import org.wso2.carbon.identity.sso.saml.util.SAMLSOAPUtils;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPMessage;

/**
 * This is the entry point for authentication process in an ECP-SSO scenario. This servlet is registered
 * with the URL pattern /ecp and act as the control servlet for browser-less clients.
 * The message flow of an ECP scenario is as follows.
 * <ol>
 * <li>ECP sends a SAML Request via SAML SOAP Binding to the https://<ip>:<port>/ecp endpoint.</li>
 * <li>Basic Authorization credentials are sent to the servlet in the Authorization header.</li>
 * <li>The end point validates the SOAP bound ECP Request and extract the SAML Request from it.</li>
 * <li>Then the servlet forwards the request to the https://<ip>:<port>/samlsso endpoint</li>
 * </ol>
 */

public class SAMLECPProviderServlet extends HttpServlet {
    private static Log log = LogFactory.getLog(SAMLECPProviderServlet.class);

    protected void doGet(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse) throws ServletException, IOException {
        String soapFault = SAMLSOAPUtils.createSOAPFault("Unsupported Request POST", "Client");
        log.error(soapFault);
        PrintWriter out = httpServletResponse.getWriter();
        httpServletResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        httpServletResponse.setContentType("text/html;charset=UTF-8");
        out.print(soapFault);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            handleRequest(req, resp);
        } finally {
            SAMLSSOUtil.removeSaaSApplicationThreaLocal();
            SAMLSSOUtil.removeUserTenantDomainThreaLocal();
            SAMLSSOUtil.removeTenantDomainFromThreadLocal();
        }
    }


    private void handleRequest(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            if (req.getHeader("Authorization") == null) {
                String err = "Authorization Header cannot be Empty";
                log.error(err);
                throw new IdentitySAML2ECPException(err);
            }
        MessageFactory messageFactory = MessageFactory.newInstance();
        InputStream inStream = req.getInputStream();
        SOAPMessage soapMessage = messageFactory.createMessage(new MimeHeaders(), inStream);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        soapMessage.writeTo(out);
        String strMsg = new String(out.toByteArray(), Charset.forName("UTF-8"));
            if (log.isDebugEnabled()) {
                log.debug("ECP Request : " + strMsg);
            }
        String samlRequest = SAMLSOAPUtils.decodeSOAPMessage(soapMessage);
        SamlSSORequestWrapper samlSSORequestWrapper = new SamlSSORequestWrapper(req);
        samlSSORequestWrapper.setParameter(SAMLSSOConstants.SAML_REQUEST, samlRequest);
        samlSSORequestWrapper.setParameter("isECP", "true");
        RequestDispatcher dispatcher = req.getRequestDispatcher("/samlsso");
        log.info("Forwarding the ECP request to SAMLSSO Servlet");
        dispatcher.forward(samlSSORequestWrapper, resp);

        } catch (Exception e) {
            SAMLSOAPUtils.sendSOAPFault(resp, e.getMessage(), "Client");
            log.error("Error processing the SOAP request");

        }
    }
}
