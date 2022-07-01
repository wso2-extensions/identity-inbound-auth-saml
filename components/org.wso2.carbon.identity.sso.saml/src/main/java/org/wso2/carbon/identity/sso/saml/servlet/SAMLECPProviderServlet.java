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
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.sso.saml.SAMLECPConstants;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ECPException;
import org.wso2.carbon.identity.sso.saml.model.SamlSSORequestWrapper;
import org.wso2.carbon.identity.sso.saml.util.SAMLSOAPUtils;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.MimeHeaders;
import jakarta.xml.soap.SOAPException;
import jakarta.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;

/**
 * This is the entry point for authentication process in an ECP-SSO scenario. This servlet is registered
 * with the URL pattern /ecp and act as the control servlet for browser-less clients.
 * The message flow of an ECP scenario is as follows.
 * <ol>
 * <li>ECP sends a SAML Request via SAML SOAP Binding to the https://<ip>:<port>/samlecp endpoint.</li>
 * <li>Basic Authorization credentials are sent to the servlet in the Authorization header.</li>
 * <li>The end point validates the SOAP bound ECP Request and extract the SAML Request from it.</li>
 * <li>Then the servlet forwards the request to the https://<ip>:<port>/samlsso endpoint</li>
 * </ol>
 */

public class SAMLECPProviderServlet extends HttpServlet {

    private static final Log log = LogFactory.getLog(SAMLECPProviderServlet.class);

    protected void doGet(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse) {
        String err = "Unsupported Request GET";
        SAMLSOAPUtils.sendSOAPFault(httpServletResponse, err, SAMLECPConstants.FaultCodes.SOAP_FAULT_CODE_CLIENT);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException {
        handleRequest(req, resp);
    }

    private void handleRequest(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException {
        try {
            if (StringUtils.isBlank(req.getHeader(SAMLECPConstants.AUTHORIZATION_HEADER))) {
                String message = "Authorization Header Not Found";
                SAMLSOAPUtils.sendSOAPFault(resp, message, SAMLECPConstants.FaultCodes.SOAP_FAULT_CODE_CLIENT);
                log.error(message);
            } else {
                InputStream inputStream = getInputStreamFromServletRequest(req);
                SOAPMessage soapMessage = createSOAPMessagefromInputStream(inputStream);
                inputStream.close();
                if (log.isDebugEnabled()) {
                    String strMsg = convertSOAPMsgToOutputStream(soapMessage);
                    log.debug("ECP Request : " + strMsg);
                }
                String samlRequest = SAMLSOAPUtils.decodeSOAPMessage(soapMessage);
                SamlSSORequestWrapper samlSSORequestWrapper = new SamlSSORequestWrapper(req);
                samlSSORequestWrapper.setParameter(SAMLSSOConstants.SAML_REQUEST, samlRequest);
                samlSSORequestWrapper.setParameter(SAMLECPConstants.IS_ECP_REQUEST, Boolean.toString(true));
                RequestDispatcher dispatcher = req.getRequestDispatcher(SAMLSSOConstants.SAMLSSO_URL);
                dispatcher.forward(samlSSORequestWrapper, resp);
            }
        } catch (IdentitySAML2ECPException e) {
            SAMLSOAPUtils.sendSOAPFault(resp, e.getMessage(), SAMLECPConstants.FaultCodes.SOAP_FAULT_CODE_CLIENT);
            String message = "Error processing the SOAP request";
            log.error(message, e);
        } catch (SOAPException | IOException | TransformerException e) {
            SAMLSOAPUtils.sendSOAPFault(resp, e.getMessage(), SAMLECPConstants.FaultCodes.SOAP_FAULT_CODE_SERVER);
            String message = "Error processing the SOAP Request";
            log.error(message, e);
        }
    }

    /**
     * This method returns the InputStream from the Servlet Request.
     * @param req ECP Servlet Request
     * @return
     * @throws IOException
     */
    private InputStream getInputStreamFromServletRequest(HttpServletRequest req) throws IOException {
        InputStream inputStream = req.getInputStream();
        return inputStream;
    }

    /**
     * This method returns s SOAP message from the given Servlet Input Stream.
     * @param inputStream InputStream from the servlet Request
     * @return
     * @throws IOException
     * @throws SOAPException
     */
    private SOAPMessage createSOAPMessagefromInputStream(InputStream inputStream) throws SOAPException, IOException {
        SOAPMessage soapMessage;
        MessageFactory messageFactory = MessageFactory.newInstance();
        soapMessage = messageFactory.createMessage(new MimeHeaders(), inputStream);
        return soapMessage;
    }

    /**
     * This method converts SOAPMessage to OutputStream and return the String.
     * @param soapMessage SOAPMessage from the InputStream.
     * @return
     * @throws SOAPException
     * @throws IOException
     */
    private String convertSOAPMsgToOutputStream(SOAPMessage soapMessage) throws SOAPException, IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        soapMessage.writeTo(outputStream);
        String strMsg = new String(outputStream.toByteArray(), StandardCharsets.UTF_8);
        outputStream.close();
        return strMsg;
    }
}
