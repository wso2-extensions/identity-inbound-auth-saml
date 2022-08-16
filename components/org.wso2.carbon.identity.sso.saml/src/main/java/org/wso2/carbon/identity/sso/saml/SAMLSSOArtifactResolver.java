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

package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.builders.ResponseBuilder;
import org.wso2.carbon.identity.sso.saml.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.sso.saml.dao.SAML2ArtifactInfoDAO;
import org.wso2.carbon.identity.sso.saml.dao.impl.SAML2ArtifactInfoDAOImpl;
import org.wso2.carbon.identity.sso.saml.dto.SAML2ArtifactInfo;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.exception.ArtifactBindingException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.user.api.UserStoreException;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.UUID;

/**
 * This class is used to resolve a previously issued SAML2 artifact.
 */
public class SAMLSSOArtifactResolver {

    private static final Log log = LogFactory.getLog(SAMLSSOArtifactResolver.class);

    /**
     * Build and return an ArtifactResponse object when SAML artifactResolve is given, according to the section
     * 3.5 of <a href="http://saml.xml.org/saml-specifications">SAML2 core specification</a>.
     *
     * @param artifactResolve SAML artifactResolve given by the requester.
     * @return Built ArtifactResponse object.
     */
    public ArtifactResponse resolveArtifact(ArtifactResolve artifactResolve) throws ArtifactBindingException {

        Response response = null;
        ArtifactResponse artifactResponse = null;
        String artifact = artifactResolve.getArtifact().getArtifact();
        try {
            // Decode and depart SAML artifactResolve.
            byte[] artifactArray = Base64.decode(artifact);
            byte[] sourceId = Arrays.copyOfRange(artifactArray, 4, 24);
            String sourceIdString = String.format("%040x", new BigInteger(1, sourceId));
            byte[] messageHandler = Arrays.copyOfRange(artifactArray, 24, 44);
            String messageHandlerString = String.format("%040x", new BigInteger(1, messageHandler));

            // Get SAML artifactResolve data from the database.
            SAML2ArtifactInfoDAO saml2ArtifactInfoDAO = new SAML2ArtifactInfoDAOImpl();
            SAML2ArtifactInfo artifactInfo = saml2ArtifactInfoDAO.getSAMLArtifactInfo(sourceIdString,
                    messageHandlerString);

            if (artifactInfo != null && artifactInfo.getAuthnReqDTO() != null) {
                startTenantFlow(artifactInfo.getAuthnReqDTO().getTenantDomain());
                if (validateArtifactResolve(artifactResolve, artifactInfo)) {
                    // Building Response.
                    ResponseBuilder respBuilder = SAMLSSOUtil.getResponseBuilder();
                    if (respBuilder != null) {
                        response = respBuilder.buildResponse(artifactInfo.getAuthnReqDTO(), artifactInfo.getSessionID(),
                                artifactInfo.getInitTimestamp(), artifactInfo.getAssertionID());

                    } else {
                        throw new ArtifactBindingException("Could not create a ResponseBuilder for SAML2 artifact " +
                                "resolution.");
                    }
                }
            } else {
                log.warn("Invalid artifact received to Artifact Resolution endpoint: " + artifact);
            }

            artifactResponse = buildArtifactResponse(response, artifactResolve, artifactInfo);

        } catch (IdentityException e) {
            throw new ArtifactBindingException("Error while building response for SAML2 artifact: " + artifact, e);
        }
        catch (Base64DecodingException e) {
            throw new ArtifactBindingException("Error while Base64 decoding SAML2 artifact: " + artifact, e);
        } finally {
            endTenantFlow();
        }

        return artifactResponse;
    }

    /**
     * Validate the artifact resolve request for issuer, validity period and signature.
     *
     * @param artifactResolve ArtifactResolve object to be validated.
     * @throws IdentityException
     * @throws ArtifactBindingException
     */
    private boolean validateArtifactResolve(ArtifactResolve artifactResolve, SAML2ArtifactInfo artifactInfo)
            throws IdentityException, ArtifactBindingException {

        // Checking for artifactResolve validity period.
        DateTime currentTime = new DateTime();
        if (!artifactInfo.getExpTimestamp().isAfter(currentTime)) {
            log.warn("Artifact validity period (" + artifactInfo.getExpTimestamp() + ") has been " +
                        "exceeded for artifact: " + artifactResolve.getArtifact().getArtifact());
            return false;
        }

        // Checking for issuer.
        if (StringUtils.equals(artifactInfo.getAuthnReqDTO().getIssuer(), artifactResolve.getIssuer().getValue())) {

            String tenantDomain = artifactInfo.getAuthnReqDTO().getTenantDomain();
            SAMLSSOServiceProviderDO serviceProviderDO = SAMLSSOUtil.getSPConfig(
                    tenantDomain, SAMLSSOUtil.splitAppendedTenantDomain(artifactResolve.getIssuer().getValue()));

            // Checking for signature.
            if (serviceProviderDO.isDoValidateSignatureInArtifactResolve()) {
                return validateArtifactResolveSignature(artifactResolve, serviceProviderDO);
            }
        } else {
            log.warn("Artifact Resolve Issuer: " + artifactResolve.getIssuer().getValue() + " is not valid.");
            return false;
        }

        return true;
    }

    /**
     * Validate the signature of SAML2 artifact resolve object.
     *
     * @param artifactResolve   Artifact resolve object.
     * @param serviceProviderDO Service provider object.
     * @throws ArtifactBindingException
     */
    private boolean validateArtifactResolveSignature(ArtifactResolve artifactResolve,
                                                  SAMLSSOServiceProviderDO serviceProviderDO)
            throws ArtifactBindingException {

        if (log.isDebugEnabled()) {
            log.debug("Validating Artifact Resolve signature for artifact: " +
                    artifactResolve.getArtifact().getArtifact() + ", issuer: " +
                    artifactResolve.getIssuer().getValue());
        }

        if (artifactResolve.getSignature() == null) {
            log.warn("Signature was not found in the SAML2 Artifact Resolve with artifact: " +
                        artifactResolve.getArtifact().getArtifact() + " issuer: " +
                        artifactResolve.getIssuer().getValue());
            return false;
        }
        SignatureImpl signImpl = (SignatureImpl) artifactResolve.getSignature();

        if (serviceProviderDO.getX509Certificate() == null) {
            throw new ArtifactBindingException("Artifact resolve signature validation is enabled, but SP " +
                    "doesn't have a certificate");
        }

        try {
            BasicX509Credential credential = new BasicX509Credential(serviceProviderDO.getX509Certificate());
            SignatureValidator.validate(signImpl, credential);
            return true;
        } catch (SignatureException e) {
            String message = "Signature validation failed for SAML2 Artifact Resolve with artifact: " +
                    artifactResolve.getArtifact().getArtifact() + " issuer: " +
                    artifactResolve.getIssuer().getValue();
            log.warn(message);
            // Logging the error only in debug mode since this is an open endpoint.
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            return false;
        }
    }

    /**
     * Build ArtifactResponse object wrapping response inside.
     *
     * @param response        Response object to be sent.
     * @param artifactResolve Artifact resolve object received.
     * @param artifactInfo    SAML2ArtifactInfo object constructed from the data on DB.
     * @return Built artifact response object.
     * @throws IdentityException
     */
    private ArtifactResponse buildArtifactResponse(Response response, ArtifactResolve artifactResolve,
                                                   SAML2ArtifactInfo artifactInfo) throws IdentityException {

        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        SAMLObjectBuilder<ArtifactResponse> artifactResolveBuilder =
                (SAMLObjectBuilder<ArtifactResponse>) builderFactory.getBuilder(ArtifactResponse.DEFAULT_ELEMENT_NAME);
        ArtifactResponse artifactResponse = artifactResolveBuilder.buildObject();

        // Build ArtifactResponse object
        artifactResponse.setVersion(SAMLVersion.VERSION_20);
        artifactResponse.setID(UUID.randomUUID().toString());
        artifactResponse.setIssueInstant(artifactResolve.getIssueInstant());
        artifactResponse.setInResponseTo(artifactResolve.getID());
        artifactResponse.setIssuer(SAMLSSOUtil.getIssuer());

        SAMLObjectBuilder<StatusCode> statusCodeBuilder =
                (SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS);
        SAMLObjectBuilder<Status> statusBuilder =
                (SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);
        artifactResponse.setStatus(status);
        artifactResponse.setMessage(response);

        if (artifactInfo != null) {
            SAMLSSOAuthnReqDTO authReqDTO = artifactInfo.getAuthnReqDTO();
            SAMLSSOUtil.setSignature(artifactResponse, authReqDTO.getSigningAlgorithmUri(), authReqDTO.getDigestAlgorithmUri
                    (), new SignKeyDataHolder(authReqDTO.getUser().getAuthenticatedSubjectIdentifier()));
        }

        return artifactResponse;
    }

    private void startTenantFlow(String tenantDomain) throws IdentityException {

        if (StringUtils.isBlank(tenantDomain)) {
            return;
        }

        int tenantId;
        try {
            tenantId = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
            if (tenantId == -1) {
                // invalid tenantId, hence throw exception to avoid setting invalid tenant info.
                String message = "Invalid Tenant Domain : " + tenantDomain;
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }
                throw IdentityException.error(message);
            }
        } catch (UserStoreException e) {
            String message = "Error occurred while getting tenant ID from tenantDomain " + tenantDomain;
            throw IdentityException.error(message, e);
        }

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        carbonContext.setTenantId(tenantId);
        carbonContext.setTenantDomain(tenantDomain);
    }

    private void endTenantFlow() {

        PrivilegedCarbonContext.endTenantFlow();
    }
}
