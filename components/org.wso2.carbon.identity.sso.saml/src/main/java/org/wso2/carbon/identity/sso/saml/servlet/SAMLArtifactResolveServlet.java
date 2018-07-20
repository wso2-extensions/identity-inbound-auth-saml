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
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.opensaml.xml.validation.ValidationException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.SAMLSSOArtifactResolver;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.exception.ArtifactBindingException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.ui.CarbonUIUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
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
            String id = null;
            String samlArtifact = null;
            DateTime issueInstant = null;
            try {
                MessageFactory messageFactory = MessageFactory.newInstance();
                InputStream inStream = req.getInputStream();
                SOAPMessage soapMessage = messageFactory.createMessage(new MimeHeaders(), inStream);
                SOAPBody soapBody = soapMessage.getSOAPBody();
                Iterator iterator = soapBody.getChildElements();

                while (iterator.hasNext()) {
                    SOAPBodyElement artifactResolveElement = (SOAPBodyElement) iterator.next();

                    if (StringUtils.equals(SAMLConstants.SAML20P_NS, artifactResolveElement.getNamespaceURI()) &&
                            StringUtils.equals(ArtifactResolve.DEFAULT_ELEMENT_LOCAL_NAME,
                                    artifactResolveElement.getLocalName())) {

                        DOMSource source = new DOMSource(artifactResolveElement);
                        StringWriter stringResult = new StringWriter();
                        TransformerFactory.newInstance().newTransformer().transform(
                                source, new StreamResult(stringResult));
                        ArtifactResolve artifactResolve =
                                (ArtifactResolve) SAMLSSOUtil.unmarshall(stringResult.toString());

                        validateArtifactResolve(artifactResolve);

                        id = URLDecoder.decode(artifactResolve.getID(), StandardCharsets.UTF_8.name());
                        issueInstant = artifactResolve.getIssueInstant();
                        samlArtifact = URLDecoder.decode(artifactResolve.getArtifact().getArtifact(),
                                StandardCharsets.UTF_8.name());
                    }
                }
            } catch (SOAPException e) {
                throw new ServletException("Error while extracting SOAP body from the request.", e);
            } catch (TransformerException e) {
                throw new ServletException("Error while extracting ArtifactResponse from the request.", e);
            } catch (IdentityException e) {
                throw new ServletException("Error while unmarshalling ArtifactResponse  from the request.", e);
            } catch (ArtifactBindingException e) {
                throw new ServletException("Error while validating ArtifactResolve signature.", e);
            }

            if (samlArtifact != null) {
                handleArtifact(req, resp, samlArtifact, id, issueInstant);
            } else {
                log.error("Invalid SAML Artifact Resolve request received.");
            }

        } finally {
            SAMLSSOUtil.removeSaaSApplicationThreaLocal();
            SAMLSSOUtil.removeUserTenantDomainThreaLocal();
            SAMLSSOUtil.removeTenantDomainFromThreadLocal();
        }
    }

    private void validateArtifactResolve(ArtifactResolve artifactResolve)
            throws IdentityException, ArtifactBindingException {

        SignatureImpl signImpl = (SignatureImpl)artifactResolve.getSignature();

        String tenantDomain = SAMLSSOUtil.getTenantDomainFromThreadLocal();
        SAMLSSOServiceProviderDO serviceProviderDO = SAMLSSOUtil.getSPConfig(
                tenantDomain, SAMLSSOUtil.splitAppendedTenantDomain(artifactResolve.getIssuer().getValue()));

        try {
            SAMLSignatureProfileValidator signatureProfileValidator = new SAMLSignatureProfileValidator();
            signatureProfileValidator.validate(signImpl);
        } catch (ValidationException e) {
            throw new ArtifactBindingException("Signature do not confirm to SAML signature profile. Possible XML " +
                    "Signature Wrapping Attack!", e);
        }

        if (serviceProviderDO.getSigningCertificate() == null || serviceProviderDO.getSigningCertificate().isEmpty()) {
            throw new ArtifactBindingException("Artifact resolve signature validation is enabled, but SP " +
                    "doesn't have a certificate");
        }

        try {
            SignatureValidator validator = new SignatureValidator((Credential) serviceProviderDO.getX509Certificate());
            validator.validate(signImpl);
        } catch (ValidationException e) {
            throw new ArtifactBindingException("Signature validation failed for SAML Response", e);
        }
    }

    /**
     * Resolve the received SAML artifact.
     *
     * @param req          HttpServletRequest.
     * @param resp         HttpServletResponse.
     * @param samlArt      Received SAMl artifact.
     * @param id           Received Id of the resolve request.
     * @param issueInstant Received issue instant of the resolve request.
     * @throws IOException
     * @throws ServletException
     */
    private void handleArtifact(HttpServletRequest req, HttpServletResponse resp, String samlArt, String id,
                                DateTime issueInstant) throws IOException, ServletException {

        if (log.isDebugEnabled()) {
            log.debug("Resolving SAML2 artifact: " + samlArt);
        }

        try {

            Response response = new SAMLSSOArtifactResolver().resolveArtifact(samlArt);

            if (log.isDebugEnabled()) {
                String responseString = null;
                if (response != null) {
                    responseString = SAMLSSOUtil.marshall(response);
                }
                log.debug("Generated SAML2 artifact response for the artifact: [" + samlArt +
                        "] -> " + responseString);
            }

            ArtifactResponse artifactResponse = buildArtifactResponse(response, id, issueInstant);
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
                    ", ID: " + id, e);
            sendNotification(SAMLSSOConstants.Notification.EXCEPTION_STATUS_ARTIFACT_RESOLVE,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, req, resp);
        } catch (ArtifactBindingException e) {
            log.error("Error while creating SOAP request message for the artifact: " + samlArt +
                    ", issueInstant: " + issueInstant + ", ID: " + id, e);
            sendNotification(SAMLSSOConstants.Notification.EXCEPTION_STATUS_ARTIFACT_RESOLVE,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, req, resp);
        }
    }

    /**
     * Build ArtifactResponse object wrapping response inside.
     *
     * @param response     Response object to be sent.
     * @param requestId    ID of the SAMl ArtifactResolve object. Goes back as the InResponseTo in ArtifactResponse.
     * @param issueInstant Issue instance came with SAMl ArtifactResolve object.
     * @return Built artifact response object.
     * @throws IdentityException
     */
    private ArtifactResponse buildArtifactResponse(Response response, String requestId, DateTime issueInstant)
            throws IdentityException {

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<ArtifactResponse> artifactResolveBuilder =
                (SAMLObjectBuilder<ArtifactResponse>) builderFactory.getBuilder(ArtifactResponse.DEFAULT_ELEMENT_NAME);
        ArtifactResponse artifactResponse = artifactResolveBuilder.buildObject();

        // Build ArtifactResponse object
        artifactResponse.setVersion(SAMLVersion.VERSION_20);
        artifactResponse.setID(UUID.randomUUID().toString());
        artifactResponse.setIssueInstant(issueInstant);
        artifactResponse.setInResponseTo(requestId);
        artifactResponse.setIssuer(SAMLSSOUtil.getIssuer());

        SAMLObjectBuilder<StatusCode> statusCodeBuilder =
                (SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        SAMLObjectBuilder<Status> statusBuilder =
                (SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);
        artifactResponse.setStatus(status);
        artifactResponse.setMessage(response);

        // TODO: 7/6/18 Sign response
        return artifactResponse;
    }

    /**
     * Build a SOAP Message.
     *
     * @param samlMessage SAMLObject.
     * @return Envelope soap envelope
     */
    private Envelope buildSOAPMessage(SAMLObject samlMessage) {

        XMLObjectBuilderFactory builderFactory = org.opensaml.xml.Configuration.getBuilderFactory();

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

        String redirectURL = CarbonUIUtil.getAdminConsoleURL(req);
        redirectURL = redirectURL.replace("samlsso/carbon/",
                "authenticationendpoint/samlsso_notification.do");
        //TODO Send status codes rather than full messages in the GET request
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put(SAMLSSOConstants.STATUS, status);
        queryParams.put(SAMLSSOConstants.STATUS_MSG, message);
        resp.sendRedirect(FrameworkUtils.appendQueryParamsToUrl(redirectURL, queryParams));
    }
}
