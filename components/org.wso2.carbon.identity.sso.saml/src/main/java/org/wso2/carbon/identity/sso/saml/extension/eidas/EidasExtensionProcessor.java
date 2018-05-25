/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml.extension.eidas;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.w3c.dom.NodeList;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.extension.SAMLExtensionProcessor;
import org.wso2.carbon.identity.sso.saml.extension.eidas.model.RequestedAttributes;
import org.wso2.carbon.identity.sso.saml.extension.eidas.model.SPType;
import org.wso2.carbon.identity.sso.saml.extension.eidas.util.EidasConstants;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;

/**
 * This class is used to process and validate the eIDAS SAML extensions.
 */
public class EidasExtensionProcessor implements SAMLExtensionProcessor {
    private static Log log = LogFactory.getLog(EidasExtensionProcessor.class);
    private static String errorMsg = "Mandatory Attribute not found.";

    /**
     * Check whether the SAML authentication request can be handled by the eIDAS extension processor.
     *
     * @param request SAML request
     * @return true if the request can be handled
     * @throws IdentitySAML2SSOException
     */
    @Override
    public boolean canHandle(RequestAbstractType request) throws IdentitySAML2SSOException {

        boolean canHandle = request.getNamespaces().stream().anyMatch(namespace -> EidasConstants.EIDAS_NS.equals(
                namespace.getNamespaceURI()));
        if (canHandle) {
            if (log.isDebugEnabled()) {
                log.debug("Request in type: " + request.getClass().getSimpleName() + " can be handled by the " +
                        "EidasExtensionProcessor.");
            }
        }
        return canHandle;
    }

    /**
     * Check whether the SAML response can be handled by the eIDAS extension processor.
     *
     * @param authReqDTO Authentication request data object
     * @return true if the request can be handled
     * @throws IdentitySAML2SSOException
     */
    @Override
    public boolean canHandle(StatusResponseType response, Assertion assertion, SAMLSSOAuthnReqDTO authReqDTO)
            throws IdentitySAML2SSOException {

        String requestType = authReqDTO.getProperty(EidasConstants.EIDAS_REQUEST);
        boolean canHandle = false;
        if (requestType != null) {
            canHandle = EidasConstants.EIDAS_PREFIX.equals(requestType);
            if (canHandle) {
                if (log.isDebugEnabled()) {
                    log.debug("Response in type: " + response.getClass().getSimpleName() + " can be handled by the " +
                            "EidasExtensionProcessor.");
                }
            }
        }
        return canHandle;
    }

    /**
     * Process and Validate the SAML extensions in authentication request for EIDAS message format.
     *
     * @param request        Authentication request
     * @param validationResp reqValidationResponseDTO
     * @throws IdentityException
     */
    @Override
    public void processSAMLExtensions(RequestAbstractType request, SAMLSSOReqValidationResponseDTO validationResp)
            throws IdentitySAML2SSOException {

        if (request instanceof AuthnRequest) {
            if (log.isDebugEnabled()) {
                log.debug("Process and validate the extensions in SAML request from the issuer : " +
                        validationResp.getIssuer() + " for EIDAS message format.");
            }
            Extensions extensions = request.getExtensions();
            if (extensions != null) {
                validateForceAuthn(validationResp);
                validateIsPassive(validationResp);
                validateAuthnContextComparison(validationResp);
                validateSPType(validationResp, extensions);

                processRequestedAttributes(validationResp, extensions);
            }
        }
    }

    /**
     * Process and Validate a response against the SAML request with extensions for EIDAS message format.
     *
     * @param response    SAML response
     * @param assertion   SAML assertion
     * @param authReqDTO Authentication request data object
     * @throws IdentitySAML2SSOException
     */
    @Override
    public void processSAMLExtensions(StatusResponseType response, Assertion assertion, SAMLSSOAuthnReqDTO authReqDTO)
            throws IdentitySAML2SSOException {

        if (response instanceof Response) {
            if (log.isDebugEnabled()) {
                log.debug("Process and validate a response against the SAML request with extensions" +
                        " for EIDAS message format");
            }
            validateMandatoryRequestedAttr((Response) response, assertion, authReqDTO);
            setAuthnContextClassRef(assertion, authReqDTO);
        }
    }

    private void validateMandatoryRequestedAttr(Response response, Assertion assertion, SAMLSSOAuthnReqDTO authReqDTO) {

        List<String> mandatoryClaims = getMandatoryAttributes(authReqDTO);
        boolean isMandatoryClaimPresent = validateMandatoryClaims(assertion, mandatoryClaims);
        if (!isMandatoryClaimPresent) {
            response.setStatus(SAMLSSOUtil.buildResponseStatus(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR,
                    errorMsg));
            if (CollectionUtils.isNotEmpty(assertion.getAttributeStatements())) {
                assertion.getAttributeStatements().clear();
            }

            NameID nameId = new NameIDBuilder().buildObject();
            nameId.setValue("NotAvailable");
            nameId.setFormat(NameIdentifier.UNSPECIFIED);
            assertion.getSubject().setNameID(nameId);
            return;
        }
        setAttributeNameFormat(assertion.getAttributeStatements());
    }

    private void setAuthnContextClassRef(Assertion assertion, SAMLSSOAuthnReqDTO authReqDTO) {

        assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef()
                .setAuthnContextClassRef(authReqDTO.getAuthenticationContextClassRefList().get(0)
                        .getAuthenticationContextClassReference());
    }

    private void processRequestedAttributes(SAMLSSOReqValidationResponseDTO validationResp, Extensions extensions)
            throws IdentitySAML2SSOException {

        if (isNotEmpty(extensions.getUnknownXMLObjects(RequestedAttributes.DEFAULT_ELEMENT_NAME))) {
            XMLObject requestedAttrs = extensions.getUnknownXMLObjects(RequestedAttributes.DEFAULT_ELEMENT_NAME).get(0);
            NodeList nodeList = requestedAttrs.getDOM().getChildNodes();
            validationResp.setRequestedAttributes(new ArrayList<>());
            validationResp.getProperties().put(EidasConstants.EIDAS_REQUEST, EidasConstants.EIDAS_PREFIX);

            for (int i = 0; i < nodeList.getLength(); i++) {
                ClaimMapping claimMapping = new ClaimMapping();
                Claim remoteClaim = new Claim();
                String nameFormat = nodeList.item(i).getAttributes().getNamedItem(
                        EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT).getNodeValue();
                validateAttributeNameFormat(validationResp, nameFormat);
                remoteClaim.setClaimUri(nodeList.item(i).getAttributes().getNamedItem(
                        EidasConstants.EIDAS_ATTRIBUTE_NAME).getNodeValue());
                claimMapping.setRemoteClaim(remoteClaim);
                claimMapping.setRequested(true);
                claimMapping.setMandatory(Boolean.parseBoolean(nodeList.item(i).getAttributes().getNamedItem(
                        EidasConstants.EIDAS_ATTRIBUTE_REQUIRED).getNodeValue()));
                validationResp.getRequestedAttributes().add(claimMapping);
            }
        }
    }

    private void validateAttributeNameFormat(SAMLSSOReqValidationResponseDTO validationResp, String nameFormat)
            throws IdentitySAML2SSOException {

        if (!nameFormat.equals(EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT_URI)) {
            String errorResp;
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, "NameFormat should be " +
                                EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT_URI,
                        validationResp.getDestination());
            } catch (IOException | IdentityException e) {
                throw new IdentitySAML2SSOException("Issue in building error response.", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Invalid Request message. NameFormat found " + nameFormat);
            }
            validationResp.setResponse(errorResp);
            validationResp.setValid(false);
        }
    }

    private void validateSPType(SAMLSSOReqValidationResponseDTO validationResp, Extensions extensions)
            throws IdentitySAML2SSOException {

        if (isNotEmpty(extensions.getUnknownXMLObjects(SPType.DEFAULT_ELEMENT_NAME))) {
            XMLObject spType = extensions.getUnknownXMLObjects(SPType.DEFAULT_ELEMENT_NAME).get(0);
            if (log.isDebugEnabled()) {
                log.debug("Process the SP Type: " + spType + " in the EIDAS message");
            }

            if (spType != null && isValidSPType((XSAnyImpl) spType)) {
                String errorResp;
                try {
                    errorResp = SAMLSSOUtil.buildErrorResponse(
                            SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, "SP Type should be either public or private.",
                            validationResp.getDestination());
                } catch (IOException | IdentityException e) {
                    throw new IdentitySAML2SSOException("Issue in building error response.", e);
                }
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Request message. SP Type found " + spType.getDOM().getNodeValue());
                }
                validationResp.setResponse(errorResp);
                validationResp.setValid(false);
            }
        }
    }

    private boolean isValidSPType(XSAnyImpl spType) {

        return !spType.getTextContent().equals(EidasConstants.EIDAS_SP_TYPE_PUBLIC) &&
                !spType.getTextContent().equals(EidasConstants.EIDAS_SP_TYPE_PRIVATE);
    }

    private boolean validateMandatoryClaims(Assertion assertion, List<String> mandatoryClaims) {

        boolean isMandatoryClaimPresent = false;
        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        if (isNotEmpty(attributeStatements)) {
            for (String mandatoryClaim : mandatoryClaims) {
                if (log.isDebugEnabled()) {
                    log.debug("Validating the mandatory claim :" + mandatoryClaim);
                }
                for (AttributeStatement attributeStatement : attributeStatements) {
                    if (isNotEmpty(attributeStatement.getAttributes())) {
                        if (attributeStatement.getAttributes().stream().anyMatch(attribute -> attribute.getName()
                                .equals(mandatoryClaim))) {
                            isMandatoryClaimPresent = true;
                        }
                        if (isMandatoryClaimPresent) {
                            break;
                        }
                    }
                }
                if (!isMandatoryClaimPresent) {
                    break;
                }
            }
        }
        return isMandatoryClaimPresent;
    }

    private List<String> getMandatoryAttributes(SAMLSSOAuthnReqDTO authReqDTO) {

        return authReqDTO.getRequestedAttributes().stream().filter(ClaimMapping::isMandatory)
                .map(requestedClaim -> requestedClaim.getRemoteClaim().getClaimUri()).collect(Collectors.toList());
    }

    private void setAttributeNameFormat(List<AttributeStatement> attributeStatements) {

        attributeStatements.forEach(attributeStatement -> attributeStatement.getAttributes().forEach(attribute ->
                attribute.setNameFormat(EidasConstants.EIDAS_ATTRIBUTE_NAME_FORMAT_URI)));
    }

    private void validateIsPassive(SAMLSSOReqValidationResponseDTO validationResponseDTO)
            throws IdentitySAML2SSOException {

        String errorResp;
        if (validationResponseDTO.isPassive()) {
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "isPassive SHOULD be set to false.",
                        validationResponseDTO.getDestination());
            } catch (IOException | IdentityException e) {
                throw new IdentitySAML2SSOException("Issue in building error response.", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Invalid Request message. isPassive found " + validationResponseDTO.isPassive());
            }
            setErrorResponse(validationResponseDTO, errorResp);
        }
    }

    private void validateForceAuthn(SAMLSSOReqValidationResponseDTO validationResponseDTO)
            throws IdentitySAML2SSOException {

        String errorResp;
        if (!validationResponseDTO.isForceAuthn()) {
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "ForceAuthn MUST be set to true",
                        validationResponseDTO.getDestination());
            } catch (IOException | IdentityException e) {
                throw new IdentitySAML2SSOException("Issue in building error response.", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Invalid Request message. ForceAuthn is " + validationResponseDTO.isForceAuthn());
            }
            setErrorResponse(validationResponseDTO, errorResp);
        }
    }

    private void validateAuthnContextComparison(SAMLSSOReqValidationResponseDTO validationResponseDTO)
            throws IdentitySAML2SSOException {

        String errorResp;
        if (!AuthnContextComparisonTypeEnumeration.MINIMUM.toString().equals(validationResponseDTO
                .getRequestedAuthnContextComparison())) {
            try {
                errorResp = SAMLSSOUtil.buildErrorResponse(
                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "Comparison of RequestedAuthnContext should be minimum.",
                        validationResponseDTO.getDestination());
            } catch (IOException | IdentityException e) {
                throw new IdentitySAML2SSOException("Issue in building error response.", e);
            }
            if (log.isDebugEnabled()) {
                log.debug("Invalid Request message. Comparison of RequestedAuthnContext is " +
                        validationResponseDTO.getRequestedAuthnContextComparison());
            }
            setErrorResponse(validationResponseDTO, errorResp);
        }
    }

    private void setErrorResponse(SAMLSSOReqValidationResponseDTO validationResponseDTO, String errorResp) {

        validationResponseDTO.setValid(false);
        validationResponseDTO.setResponse(errorResp);
        validationResponseDTO.setValid(false);
    }
}
