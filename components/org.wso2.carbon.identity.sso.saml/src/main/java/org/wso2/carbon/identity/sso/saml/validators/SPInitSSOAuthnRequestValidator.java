/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.sso.saml.validators;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Subject;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.dto.SAMLAuthenticationContextClassRefDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.util.List;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service.exception.OrgResourceHierarchyTraverseException;
import org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service.strategy.FirstFoundAggregationStrategy;
import org.wso2.carbon.identity.sso.saml.util.LambdaExceptionUtils;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponentHolder;
import java.util.Optional;

public class SPInitSSOAuthnRequestValidator extends SSOAuthnRequestAbstractValidator {

    private static final Log log = LogFactory.getLog(SPInitSSOAuthnRequestValidator.class);
    AuthnRequest authnReq;
    String queryString;

    public SPInitSSOAuthnRequestValidator(AuthnRequest authnReq) throws IdentityException {

        this.authnReq = authnReq;
    }

    public SPInitSSOAuthnRequestValidator(AuthnRequest authnReq, String queryString) throws IdentityException {

        this.authnReq = authnReq;
        this.queryString = queryString;
    }

    /**
     * Validates the authentication request according to SAML SSO Web Browser Specification
     *
     * @return SAMLSSOSignInResponseDTO
     * @throws org.wso2.carbon.identity.base.IdentityException
     */
    public SAMLSSOReqValidationResponseDTO validate() throws IdentityException {

        try {
            SAMLSSOReqValidationResponseDTO validationResponse = new SAMLSSOReqValidationResponseDTO();
            Issuer issuer = authnReq.getIssuer();

            // Validate the version
            if (!(SAMLVersion.VERSION_20.equals(authnReq.getVersion()))) {
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.VERSION_MISMATCH,
                        "Invalid SAML Version in Authentication Request. SAML Version should be equal to 2.0",
                        authnReq.getAssertionConsumerServiceURL());
                if (log.isDebugEnabled()) {
                    log.debug("Invalid version in the SAMLRequest" + authnReq.getVersion());
                }
                validationResponse.setResponse(errorResp);
                validationResponse.setValid(false);
                return validationResponse;
            }

            // Request issue time validation enabled.
            if (SAMLSSOUtil.isSAMLAuthenticationRequestValidityPeriodEnabled()) {
                String issueInstantInvalidationErrorMessage = validateRequestIssueInstant();
                if (issueInstantInvalidationErrorMessage != null) {
                    log.error(issueInstantInvalidationErrorMessage);
                    String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                            issueInstantInvalidationErrorMessage, null);
                    validationResponse.setResponse(errorResp);
                    validationResponse.setValid(false);
                    return validationResponse;
                }
            }

            // Issuer MUST NOT be null.
            if (StringUtils.isNotBlank(issuer.getValue())) {
                validationResponse.setIssuer(issuer.getValue());
            } else if (StringUtils.isNotBlank(issuer.getSPProvidedID())) {
                validationResponse.setIssuer(issuer.getSPProvidedID());
            } else {
                validationResponse.setValid(false);
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "Issuer/ProviderName should not be empty in the Authentication Request.",
                        authnReq.getAssertionConsumerServiceURL());
                log.debug("SAML Request issuer validation failed. Issuer should not be empty");
                validationResponse.setResponse(errorResp);
                validationResponse.setValid(false);
                return validationResponse;
            }

            // Remove the appended tenant domain from the issuer.
            String issuerName = splitAppendedTenantDomain(issuer.getValue());

            String tenantDomain = SAMLSSOUtil.getTenantDomainFromThreadLocal();

            Subject subject = authnReq.getSubject();
            if (log.isDebugEnabled()) {
                log.debug("Validating SAML Request  of the Issuer :" + issuerName + " of tenant domain:" + tenantDomain);
            }

            // Check whether SP is registered or not.
            // Try to resolve SP config from the organization hierarchy if accessing org id is present,
            // otherwise fall back to tenant-based lookup.
            String accessingOrgId = PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .getApplicationResidentOrganizationId();
            SAMLSSOServiceProviderDO serviceProviderConfigs;
            if (accessingOrgId != null) {
                serviceProviderConfigs = resolveServiceProviderConfigFromOrgHierarchy(issuerName, accessingOrgId);
            } else {
                serviceProviderConfigs = SAMLSSOUtil.getServiceProviderConfig(issuerName, tenantDomain);
            }
            if (serviceProviderConfigs == null) {
                String msg = "A Service Provider with the Issuer '" + validationResponse.getIssuer() + "' is not " +
                        "registered. Service Provider should be registered in advance.";
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg,
                        authnReq.getAssertionConsumerServiceURL());
                log.warn(msg);
                validationResponse.setResponse(errorResp);
                validationResponse.setValid(false);
                return validationResponse;
            } else if (SAMLSSOUtil.getIssuerWithQualifierInThreadLocal() != null) {
                // Validation response's Issuer is set to Issuer With Qualifier.
                validationResponse.setIssuerQualifier(SAMLSSOUtil.getIssuerQualifier());
                validationResponse.setIssuer(SAMLSSOUtil.getIssuerWithQualifierInThreadLocal());
            }

            // Validate signature if request signature validation enabled.
            if (serviceProviderConfigs.isDoValidateSignatureInRequests()) {
                List<String> idpUrlSet = SAMLSSOUtil.getDestinationFromTenantDomain(tenantDomain);
                if (authnReq.getDestination() == null
                        || !idpUrlSet.contains(authnReq.getDestination())) {
                    String msg = "Destination validation for Authentication Request failed. " +
                            "Received: [" + authnReq.getDestination() + "]." +
                            " Expected one in the list: [" + StringUtils.join(idpUrlSet, ',') + "]";
                    log.warn(msg);
                    String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                            msg, authnReq.getAssertionConsumerServiceURL());
                    validationResponse.setResponse(errorResp);
                    validationResponse.setValid(false);
                    return validationResponse;
                }

                // Check whether certificate is expired or not before the signature validation.
                boolean isCertificateExpired = false;
                if (SAMLSSOUtil.isSpCertificateExpiryValidationEnabled()) {
                    isCertificateExpired = SAMLSSOUtil.isCertificateExpired(serviceProviderConfigs.getX509Certificate());
                }
                if (isCertificateExpired) {
                    String msg = "The Signature validation validation failed as the SP certificate is expired, of " +
                            "Issuer" + " :" + validationResponse.getIssuer() + " and tenantDomain:" + tenantDomain;
                    String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                            msg, authnReq.getAssertionConsumerServiceURL());
                    validationResponse.setResponse(errorResp);
                    validationResponse.setValid(false);
                    return validationResponse;
                }

                // Validate signature.
                boolean isSignatureValid = SAMLSSOUtil.isSignatureValid(authnReq, queryString, validationResponse
                        .getIssuer(), serviceProviderConfigs.getX509Certificate());
                if (!isSignatureValid) {
                    String msg = "Signature validation for Authentication Request failed for the request of Issuer :" +
                            validationResponse.getIssuer() + " in tenantDomain:" + tenantDomain;
                    log.warn(msg);
                    String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                            msg, authnReq.getAssertionConsumerServiceURL());
                    validationResponse.setResponse(errorResp);
                    validationResponse.setValid(false);
                    return validationResponse;
                }

            } else {
                // Validate the assertion consumer url,  only if request is not signed.
                String acsUrl = authnReq.getAssertionConsumerServiceURL();
                if (StringUtils.isNotEmpty(acsUrl) && !serviceProviderConfigs.getAssertionConsumerUrlList()
                        .contains(acsUrl)) {
                    String msg = "ALERT: Invalid Assertion Consumer URL value '" + acsUrl + "' in the " +
                            "AuthnRequest message from  the issuer '" + serviceProviderConfigs.getIssuer() +
                            "'. Possibly " + "an attempt for a spoofing attack";
                    log.error(msg);
                    String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                            msg, authnReq.getAssertionConsumerServiceURL());
                    validationResponse.setResponse(errorResp);
                    validationResponse.setValid(false);
                    return validationResponse;
                }
            }

            // Issuer Format attribute
            if ((StringUtils.isNotBlank(issuer.getFormat())) && !(issuer.getFormat()
                    .equals(SAMLSSOConstants.Attribute.ISSUER_FORMAT))) {
                validationResponse.setValid(false);
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "Issuer Format attribute value is invalid", authnReq.getAssertionConsumerServiceURL());
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Issuer Format attribute value " + issuer.getFormat());
                }
                validationResponse.setResponse(errorResp);
                validationResponse.setValid(false);
                return validationResponse;
            }

            //TODO : Validate the NameID Format
            if (subject != null && subject.getNameID() != null) {
                validationResponse.setSubject(subject.getNameID().getValue());
            }

            // subject confirmation should not exist
            if (subject != null && subject.getSubjectConfirmations() != null && !subject.getSubjectConfirmations()
                    .isEmpty()) {
                validationResponse.setValid(false);
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "Subject Confirmation methods should NOT be in the request.",
                        authnReq.getAssertionConsumerServiceURL());
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Request message. A Subject confirmation method found " + subject
                            .getSubjectConfirmations().get(0));
                }
                validationResponse.setResponse(errorResp);
                validationResponse.setValid(false);
                return validationResponse;
            }
            validationResponse.setId(authnReq.getID());
            validationResponse.setAssertionConsumerURL(authnReq.getAssertionConsumerServiceURL());
            validationResponse.setDestination(authnReq.getDestination());
            validationResponse.setValid(true);
            validationResponse.setPassive(authnReq.isPassive());
            validationResponse.setForceAuthn(authnReq.isForceAuthn());
            setRequestedAuthnContext(validationResponse);
            Integer index = authnReq.getAttributeConsumingServiceIndex();
            if (index != null && !(index < 1)) {              //according the spec, should be an unsigned short
                validationResponse.setAttributeConsumingServiceIndex(index);
            }
            if (log.isDebugEnabled()) {
                log.debug("Authentication Request Validation is successful..");
            }
            return validationResponse;
        } catch (Exception e) {
            throw IdentityException.error("Error validating the authentication request", e);
        }
    }

    private void setRequestedAuthnContext(SAMLSSOReqValidationResponseDTO validationResponse) {

        if (authnReq.getRequestedAuthnContext() != null) {

            if (authnReq.getRequestedAuthnContext().getComparison() == null || StringUtils
                    .isBlank(authnReq.getRequestedAuthnContext().getComparison().toString())) {
                validationResponse
                        .setRequestedAuthnContextComparison(AuthnContextComparisonTypeEnumeration.EXACT.toString());
            } else {
                validationResponse.setRequestedAuthnContextComparison(
                        authnReq.getRequestedAuthnContext().getComparison().toString());
            }
            if (authnReq.getRequestedAuthnContext().getAuthnContextClassRefs() != null) {
                authnReq.getRequestedAuthnContext().getAuthnContextClassRefs().stream().forEach(ref -> {
                    validationResponse.addAuthenticationContextClassRef(
                            new SAMLAuthenticationContextClassRefDTO(ref.getAuthnContextClassRef()));
                });
            }
        }
    }

    /**
     * Validating issueInstant time
     *
     * @return
     */
    private String validateRequestIssueInstant() {

        DateTime validFrom = authnReq.getIssueInstant();
        if (validFrom == null) {
            return "IssueInstant time is not valid.";
        }
        DateTime validTill = validFrom.plusSeconds(SAMLSSOUtil.getSAMLAuthenticationRequestValidityPeriod());
        int timeStampSkewInSeconds = IdentityUtil.getClockSkewInSeconds();

        if (validFrom.minusSeconds(timeStampSkewInSeconds).isAfterNow()) {
            return "The request IssueInstant time is 'Not Before'";
        }

        if (validTill != null && validTill.plusSeconds(timeStampSkewInSeconds).isBeforeNow()) {
            return "The request IssueInstant time is  'Not On Or After'";
        }

        if (validTill != null && validFrom.isAfter(validTill)) {
            return "The request IssueInstant time is  'Not On Or After'";
        }

        return null;
    }

    /**
     * Resolve SP config from the organization hierarchy.
     *
     * @param issuer         Issuer.
     * @param accessingOrgId Accessing organization ID.
     * @return Resolved SAML SSO Service Provider DO.
     * @throws IdentityException If an error occurs while resolving the SP config.
     */
    private SAMLSSOServiceProviderDO resolveServiceProviderConfigFromOrgHierarchy(
            String issuer, String accessingOrgId) throws IdentityException {

        try {
            return IdentitySAMLSSOServiceComponentHolder.getInstance()
                    .getOrgResourceResolverService()
                    .getResourcesFromOrgHierarchy(accessingOrgId,
                            LambdaExceptionUtils.rethrowFunction(orgId ->
                                    getServiceProviderConfig(issuer, orgId)),
                            new FirstFoundAggregationStrategy<>());
        } catch (OrgResourceHierarchyTraverseException e) {
            throw new IdentityException("Error while traversing organization hierarchy for organization id: "
                    + accessingOrgId, e);
        }
    }

    /**
     * Get SAML SSO Service Provider DO for the given issuer and organization ID.
     *
     * @param issuer         Issuer.
     * @param organizationId Organization ID.
     * @return Optional SAML SSO Service Provider DO.
     * @throws IdentityException If an error occurs while loading the SP config.
     */
    private Optional<SAMLSSOServiceProviderDO> getServiceProviderConfig(String issuer, String organizationId)
            throws IdentityException {

        try {
            String tenantDomain = IdentitySAMLSSOServiceComponentHolder.getInstance()
                    .getOrganizationManager().resolveTenantDomain(organizationId);
            SAMLSSOServiceProviderDO sp = SAMLSSOUtil.getServiceProviderConfig(
                    SAMLSSOUtil.splitAppendedTenantDomain(issuer), tenantDomain);
            return Optional.ofNullable(sp);
        } catch (OrganizationManagementException e) {
            throw new IdentityException("Error while resolving tenant domain from organization id: "
                    + organizationId, e);
        } catch (Exception e) {
            throw new IdentityException("Error while loading Service Provider config for issuer: " + issuer +
                    " in org: " + organizationId, e);
        }
    }
}
