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
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.soap.common.SOAPObjectBuilder;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOArtifactResolver;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.exception.ArtifactBindingException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPBodyElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

/**
 * This is the SAML2 artifact resolve end point for authentication process in an SSO scenario.
 * This servlet is registered with the URL pattern /samlartresolve.
 */
public class SAMLArtifactResolveServlet extends HttpServlet {

    private static final long serialVersionUID = -2505199341482721905L;
    private static final Log log = LogFactory.getLog(SAMLArtifactResolveServlet.class);

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        handleRequest(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        handleRequest(req, resp);
    }

    /**
     * All requests are handled by this handleRequest method. Request should come with a soap envelop that
     * wraps an ArtifactResolve object. First we try to extract resolve object and if successful, call
     * handle artifact method.
     *
     * @param req  HttpServletRequest object received.
     * @param resp HttpServletResponse object to be sent.
     * @throws ServletException
     * @throws IOException
     */
    private void handleRequest(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        try {
            ArtifactResolve artifactResolve = null;
            try {
                MessageFactory messageFactory = MessageFactory.newInstance();
                InputStream inStream = req.getInputStream();
                SOAPMessage soapMessage = messageFactory.createMessage(new MimeHeaders(), inStream);
                if (log.isDebugEnabled()) {
                    OutputStream outputStream = new ByteArrayOutputStream();
                    soapMessage.writeTo(outputStream);
                    log.debug("SAML2 Artifact Resolve request received: " + outputStream.toString());
                }
                SOAPBody soapBody = soapMessage.getSOAPBody();
                Iterator iterator = soapBody.getChildElements();

                while (iterator.hasNext()) {
                    SOAPBodyElement artifactResolveElement = (SOAPBodyElement) iterator.next();

                    if (StringUtils.equals(SAMLConstants.SAML20P_NS, artifactResolveElement.getNamespaceURI()) &&
                            StringUtils.equals(ArtifactResolve.DEFAULT_ELEMENT_LOCAL_NAME,
                                    artifactResolveElement.getLocalName())) {

                        DOMSource source = new DOMSource(artifactResolveElement);
                        StringWriter stringResult = new StringWriter();
                        IdentityUtil.getSecuredTransformerFactory().newTransformer().transform(
                                source, new StreamResult(stringResult));
                        artifactResolve = (ArtifactResolve) SAMLSSOUtil.unmarshall(stringResult.toString());
                    }
                }
            } catch (SOAPException e) {
                throw new ServletException("Error while extracting SOAP body from the request.", e);
            } catch (TransformerException e) {
                throw new ServletException("Error while extracting ArtifactResponse from the request.", e);
            } catch (IdentityException e) {
                throw new ServletException("Error while unmarshalling ArtifactResponse  from the request.", e);
            }

            if (artifactResolve != null) {
                handleArtifact(req, resp, artifactResolve);
            } else {
                log.error("Invalid SAML Artifact Resolve request received.");
            }

        } finally {
            SAMLSSOUtil.removeSaaSApplicationThreaLocal();
            SAMLSSOUtil.removeUserTenantDomainThreaLocal();
            SAMLSSOUtil.removeTenantDomainFromThreadLocal();
        }
    }

    /**
     * Resolve the received SAML artifact.
     *
     * @param req             HttpServletRequest.
     * @param resp            HttpServletResponse.
     * @param artifactResolve Received SAMl artifact resolve object.
     * @throws IOException
     * @throws ServletException
     */
    private void handleArtifact(HttpServletRequest req, HttpServletResponse resp, ArtifactResolve artifactResolve)
            throws IOException, ServletException {

        String id = URLDecoder.decode(artifactResolve.getID(), StandardCharsets.UTF_8.name());
        DateTime issueInstant = artifactResolve.getIssueInstant();
        String samlArt = URLDecoder.decode(artifactResolve.getArtifact().getArtifact(),
                StandardCharsets.UTF_8.name());
        String issuer = artifactResolve.getIssuer().getValue();
        artifactResolve.getArtifact().setArtifact(samlArt);

        if (log.isDebugEnabled()) {
            log.debug("Resolving SAML2 artifact: " + samlArt);
        }
        try {

            ArtifactResponse artifactResponse = new SAMLSSOArtifactResolver().resolveArtifact(artifactResolve);
            Envelope envelope = buildSOAPMessage(artifactResponse);

            String envelopeElement;
            try {
                envelopeElement = SAMLSSOUtil.marshall(envelope);
            } catch (IdentitySAML2SSOException e) {
                throw new ArtifactBindingException("Encountered error marshalling SOAP message with artifact" +
                        " response, into its DOM representation", e);
            }

            if (log.isDebugEnabled()) {
                log.debug("Artifact Response as a SOAP Message for the artifact: [" + samlArt +
                        "] -> " + envelopeElement);
            }

            resp.getWriter().write(envelopeElement);

        } catch (IdentityException e) {
            log.error("Error while resolving artifact: " + samlArt + ", issueInstant: " + issueInstant +
                    ", Issuer: " + issuer, e);
            sendNotification(SAMLSSOConstants.Notification.EXCEPTION_STATUS_ARTIFACT_RESOLVE,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, req, resp);
        } catch (ArtifactBindingException e) {
            log.error("Error while creating SOAP request message for the artifact: " + samlArt +
                    ", issueInstant: " + issueInstant + ", Issuer: " + issuer, e);
            sendNotification(SAMLSSOConstants.Notification.EXCEPTION_STATUS_ARTIFACT_RESOLVE,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, req, resp);
        }
    }

    /**
     * Build a SOAP Message.
     *
     * @param samlMessage SAMLObject.
     * @return Envelope soap envelope
     */
    private Envelope buildSOAPMessage(SAMLObject samlMessage) {

        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

        SOAPObjectBuilder<Envelope> envBuilder = (SOAPObjectBuilder<Envelope>) builderFactory.getBuilder(
                Envelope.DEFAULT_ELEMENT_NAME);
        Envelope envelope = envBuilder.buildObject();

        SOAPObjectBuilder<Body> bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory.getBuilder(
                Body.DEFAULT_ELEMENT_NAME);
        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(samlMessage);
        envelope.setBody(body);
        return envelope;
    }

    /**
     * Prompts user a notification with the status and message
     *
     * @param req
     * @param resp
     * @throws ServletException
     * @throws IOException
     */
    private void sendNotification(String status, String message, HttpServletRequest req,
                                  HttpServletResponse resp) throws ServletException, IOException {

        String redirectURL = SAMLSSOUtil.getNotificationEndpoint();

        String queryParams = "?" + SAMLSSOConstants.STATUS + "=" + URLEncoder.encode(status, "UTF-8") +
                "&" + SAMLSSOConstants.STATUS_MSG + "=" + URLEncoder.encode(message, "UTF-8");
        String queryAppendedUrl = FrameworkUtils.appendQueryParamsStringToUrl(redirectURL, queryParams);
        resp.sendRedirect(queryAppendedUrl);
    }
}
