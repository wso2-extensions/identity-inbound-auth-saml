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
        String soapFault = SAMLSOAPUtils.createSOAPFault("Unsupported Request POST"
                , SAMLSOAPUtils.SOAP_FAULT_CODE_CLIENT);
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
        samlSSORequestWrapper.setParameter(SAMLSSOConstants.ECP_ENABLED, "true");
        RequestDispatcher dispatcher = req.getRequestDispatcher("/samlsso");

        log.info("Forwarding the ECP request to SAMLSSO Servlet");
        dispatcher.forward(samlSSORequestWrapper, resp);

        } catch (IdentitySAML2ECPException e) {
            SAMLSOAPUtils.sendSOAPFault(resp, e.getMessage(), SAMLSOAPUtils.SOAP_FAULT_CODE_CLIENT);
            log.error("Error processing the SOAP request");

        } catch (Exception e) {
            SAMLSOAPUtils.sendSOAPFault(resp, e.getMessage(), SAMLSOAPUtils.SAOP_FAULT_CODE_SERVER);
            log.error("Error when forwarding the SOAP Request to the SSO Servlet");
        }
    }
}
