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
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOArtifactResolver;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SAMLSSOSoapMessageService;
import org.wso2.carbon.identity.sso.saml.builders.ResponseBuilder;
import org.wso2.carbon.identity.sso.saml.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOSessionDTO;
import org.wso2.carbon.identity.sso.saml.exception.ArtifactResolutionException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.extension.SAMLExtensionProcessor;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.ui.CarbonUIUtil;

import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import java.util.UUID;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPBodyElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;

/**
 * TODO: Class level comments
 */
public class SAMLArtifactResolveServlet extends HttpServlet {

    private static final long serialVersionUID = -5182312441482721905L;
    private static Log log = LogFactory.getLog(SAMLArtifactResolveServlet.class);

    @Override
    protected void doGet(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse) throws ServletException, IOException {
        try {
            handleRequest(httpServletRequest, httpServletResponse, false);
        } finally {
            SAMLSSOUtil.removeSaaSApplicationThreaLocal();
            SAMLSSOUtil.removeUserTenantDomainThreaLocal();
            SAMLSSOUtil.removeTenantDomainFromThreadLocal();
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        try {
            handleRequest(req, resp, true);
        } finally {
            SAMLSSOUtil.removeSaaSApplicationThreaLocal();
            SAMLSSOUtil.removeUserTenantDomainThreaLocal();
            SAMLSSOUtil.removeTenantDomainFromThreadLocal();
        }
    }

    /**
     * All requests are handled by this handleRequest method. In case of SAMLRequest the user
     * will be redirected to commonAuth servlet for authentication. Based on successful
     * authentication of the user a SAMLResponse is sent back to service provider.
     * In case of logout requests, the IDP will send logout requests
     * to the other session participants and then send the logout response back to the initiator.
     *
     * @param req
     * @param resp
     * @throws ServletException
     * @throws IOException
     */
    private void handleRequest(HttpServletRequest req, HttpServletResponse resp, boolean isPost)
            throws ServletException, IOException {

        String sessionId = null;
        Cookie ssoTokenIdCookie = getTokenIdCookie(req);

        if (ssoTokenIdCookie != null) {
            sessionId = ssoTokenIdCookie.getValue();
        }

        String queryString = req.getQueryString();
        if (log.isDebugEnabled()) {
            log.debug("Query string : " + queryString);
        }

        String id = null;
        String samlArtifact = null;
        String issueInstant = null;
        try {
            MessageFactory messageFactory = MessageFactory.newInstance();
            InputStream inStream = req.getInputStream();
            SOAPMessage soapMessage = messageFactory.createMessage(new MimeHeaders(), inStream);
            SOAPBody soapBody = soapMessage.getSOAPBody();
            Iterator iterator = soapBody.getChildElements();
            while (iterator.hasNext()) {
                SOAPBodyElement artifactResolveElement = (SOAPBodyElement) iterator.next();
                id = artifactResolveElement.getAttribute("ID");
                issueInstant = artifactResolveElement.getAttribute("IssueInstant");
                SOAPBodyElement issuerElement = (SOAPBodyElement) artifactResolveElement.getFirstChild();
                SOAPBodyElement artifactElement = (SOAPBodyElement) issuerElement.getNextSibling();
                samlArtifact = artifactElement.getFirstChild().getNodeValue();
                // TODO: 7/4/18 check whether we can convert above to ArtifactResolve object directly
            }
        } catch (SOAPException e) {
            log.error("Invalid SAML Artifact Resolve request received.");
        }

        if (samlArtifact != null) {
            handleArtifact(req, resp, samlArtifact, id, issueInstant);
        } else {
            log.error("Invalid SAML Artifact Resolve request received.");
        }
    }

    private Cookie getTokenIdCookie(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (StringUtils.equals(cookie.getName(), "samlssoTokenId")) {
                    return cookie;
                }
            }
        }
        return null;
    }

    /**
     * Resolve the received SAML artifact.
     *
     * @param req         HttpServletRequest.
     * @param resp        HttpServletResponse.
     * @param samlArt     Received SAMl artifact.
     * @throws IOException
     * @throws ServletException
     */
    private void handleArtifact(HttpServletRequest req, HttpServletResponse resp, String samlArt, String id,
                                String issueInstant) throws IOException, ServletException {

        if (log.isDebugEnabled()) {
            log.debug("Resolving SAML artifact : " + samlArt);
        }

        try {
            Assertion assertion = new SAMLSSOArtifactResolver().resolveArtifact(samlArt);

            // Building response object.
            String sessionDataKey = SAMLSSOUtil.getSessionDataKey(req);
            SAMLSSOSessionDTO sessionDTO = SAMLSSOUtil.getSessionDataFromCache(sessionDataKey);
            SAMLSSOAuthnReqDTO authnReqDTO = SAMLSSOUtil.populateAuthnReqDTOWithCachedSessionEntry(sessionDTO);

            Response response = buildResponse(assertion, authnReqDTO, issueInstant);

            if (log.isDebugEnabled()) {
                log.debug(SAMLSSOUtil.marshall(response));
            }

            // Build ArtifactResponse.
            ArtifactResponse artifactResponse = buildArtifactResponse(response, id, issueInstant);

            SAMLSSOSoapMessageService soapMessageService = new SAMLSSOSoapMessageService();
            Envelope envelope = soapMessageService.buildSOAPMessage(artifactResponse);

            String envelopeElement;

            try {
                envelopeElement = SAMLSSOUtil.marshall(envelope);
            } catch (IdentitySAML2SSOException e) {
                throw new ArtifactResolutionException("Encountered error marshalling SOAP message with artifact" +
                        " response, into its DOM representation", e);
            }

            if (log.isDebugEnabled()) {
                log.debug("Artifact Response as a SOAP Message: " + envelopeElement);
            }

            resp.getWriter().write(envelopeElement);

        } catch (IdentityException e) {
            log.error("Error while resolving artifact", e);
            sendNotification(SAMLSSOConstants.Notification.EXCEPTION_STATUS_ARTIFACT_RESOLVE,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, req, resp);
        } catch (Exception e) {
            log.error("Error while creating SOAP request message", e);
            sendNotification(SAMLSSOConstants.Notification.EXCEPTION_STATUS_ARTIFACT_RESOLVE,
                    SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, req, resp);
        }
    }

    /**
     * Build ArtifactResponse object wrapping response inside.
     *
     * @param response     Response object to be sent.
     * @param id           ID of the SAMl ArtifactResolve object. Goes back as the InResponseTo in ArtifactResponse.
     * @param issueInstant Issue instance came with SAMl ArtifactResolve object.
     * @return Built artifact response object.
     * @throws IdentityException
     */
    private ArtifactResponse buildArtifactResponse(Response response, String id, String issueInstant)
            throws IdentityException {

        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        SAMLObjectBuilder<ArtifactResponse> artifactResolveBuilder =
                (SAMLObjectBuilder<ArtifactResponse>) builderFactory.getBuilder(ArtifactResponse.DEFAULT_ELEMENT_NAME);
        ArtifactResponse artifactResponse = artifactResolveBuilder.buildObject();

        // Build ArtifactResponse object
        artifactResponse.setVersion(SAMLVersion.VERSION_20);
        artifactResponse.setID(UUID.randomUUID().toString());
        artifactResponse.setIssueInstant(new DateTime(issueInstant));
        artifactResponse.setInResponseTo(id);
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
     * Prompts user a notification with the status and message
     *
     * @param req
     * @param resp
     * @throws ServletException
     * @throws IOException
     */
    private void sendNotification(String status, String message, HttpServletRequest req,
                                  HttpServletResponse resp) throws ServletException, IOException {

        // TODO: 7/4/18 recheck
        String redirectURL = CarbonUIUtil.getAdminConsoleURL(req);
        redirectURL = redirectURL.replace("samlsso/carbon/",
                "authenticationendpoint/samlsso_notification.do");
        //TODO Send status codes rather than full messages in the GET request
        String queryParams = "?" + SAMLSSOConstants.STATUS + "=" + status + "&" +
                SAMLSSOConstants.STATUS_MSG + "=" + message;
        resp.sendRedirect(redirectURL + queryParams);
    }

    /**
     * Build Response object wrapping SAML assertion.
     *
     * @param assertion    Assertion to be sent.
     * @param authReqDTO   Authentication Request DTO object to get information.
     * @param issueInstant Issue instant came with the request.
     * @return Built Response object.
     * @throws IdentityException
     */
    private Response buildResponse(Assertion assertion, SAMLSSOAuthnReqDTO authReqDTO, String issueInstant)
            throws IdentityException {

        // TODO: 7/10/18 Double check information relevancy.
        Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();
        response.setIssuer(SAMLSSOUtil.getIssuer());
        response.setID(SAMLSSOUtil.createID());
        if (!authReqDTO.isIdPInitSSOEnabled()) {
            response.setInResponseTo(authReqDTO.getId());
        }
        response.setDestination(authReqDTO.getAssertionConsumerURL());
        response.setStatus(SAMLSSOUtil.buildResponseStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(new DateTime(issueInstant));

        for (SAMLExtensionProcessor extensionProcessor : SAMLSSOUtil.getExtensionProcessors()) {
            if (extensionProcessor.canHandle(response, assertion, authReqDTO)) {
                extensionProcessor.processSAMLExtensions(response, assertion, authReqDTO);
            }
        }

        if (authReqDTO.isDoEnableEncryptedAssertion()) {

            String domainName = authReqDTO.getTenantDomain();
            String alias = authReqDTO.getCertAlias();
            String assertionEncryptionAlgorithm = authReqDTO.getAssertionEncryptionAlgorithmUri();
            String keyEncryptionAlgorithm = authReqDTO.getKeyEncryptionAlgorithmUri();
            if (alias != null) {
                EncryptedAssertion encryptedAssertion = SAMLSSOUtil.setEncryptedAssertion(assertion,
                        assertionEncryptionAlgorithm, keyEncryptionAlgorithm, alias, domainName);
                response.getEncryptedAssertions().add(encryptedAssertion);
            } else {
                log.warn("Certificate alias is not found. Assertion is not encrypted and not included in response");
            }
        } else {
            response.getAssertions().add(assertion);
        }

        if (authReqDTO.isDoSignResponse()) {
            SAMLSSOUtil.setSignature(response, authReqDTO.getSigningAlgorithmUri(), authReqDTO.getDigestAlgorithmUri
                    (), new SignKeyDataHolder(authReqDTO.getUser().getAuthenticatedSubjectIdentifier()));
        }
        return response;
    }
}
