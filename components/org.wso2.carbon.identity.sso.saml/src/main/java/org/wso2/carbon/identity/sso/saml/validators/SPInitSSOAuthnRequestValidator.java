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
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Subject;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.dto.SAMLAuthenticationContextClassRefDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import java.util.List;

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
            Subject subject = authnReq.getSubject();
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            if (StringUtils.isEmpty(tenantDomain)) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }
            if (log.isDebugEnabled()) {
                log.debug("Validating SAML Request  of the Issuer :" + issuer + " of tenant domain:" + tenantDomain);
            }

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

            // Check whether SP is registered or not.
            SAMLSSOServiceProviderDO serviceProviderConfigs = SAMLSSOUtil.getServiceProviderConfig(validationResponse
                    .getIssuer(), tenantDomain);
            if (serviceProviderConfigs == null) {
                String msg = "A Service Provider with the Issuer '" + validationResponse.getIssuer() + "' is not " +
                        "registered. Service Provider should be registered in advance.";
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg,
                        authnReq.getAssertionConsumerServiceURL() );
                log.warn(msg);
                validationResponse.setResponse(errorResp);
                validationResponse.setValid(false);
                return validationResponse;
            }

            // Validate signature if request signature validation enabled.
            if (serviceProviderConfigs.isDoValidateSignatureInRequests()) {
                List<String> idpUrlSet = SAMLSSOUtil.getDestinationFromTenantDomain(serviceProviderConfigs
                        .getTenantDomain());
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
                if (StringUtils.isBlank(acsUrl) || !serviceProviderConfigs.getAssertionConsumerUrlList().contains
                        (acsUrl)) {
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

            String issuerQualifier = SAMLSSOUtil.getIssuerQualifier();
            String issuerWithQualifier = SAMLSSOUtil.getIssuerWithQualifier(validationResponse.getIssuer(), issuerQualifier);
            if (issuerWithQualifier != null && SAMLSSOUtil.isValidSAMLIssuer(splitAppendedTenantDomain(validationResponse
                    .getIssuer()), issuerWithQualifier, SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
                if (log.isDebugEnabled()) {
                    String message = "A SAML request with issuer: " + validationResponse.getIssuer() + " is received." +
                            " A valid Service Provider configuration with the Issuer: " + validationResponse.getIssuer() +
                            " and Issuer Qualifier: " + issuerQualifier + " is identified by the name: " + issuerWithQualifier;
                    log.debug(message);
                }
                //Validation response's Issuer is set to Issuer With Qualifier
                validationResponse.setIssuerQualifier(issuerQualifier);
                validationResponse.setIssuer(issuerWithQualifier);
            } else if (!SAMLSSOUtil.isSAMLIssuerExists(splitAppendedTenantDomain(validationResponse.getIssuer()),
                    SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
                String message = "A SAML Service Provider with the Issuer '" + validationResponse.getIssuer() + "' is"
                        + " not registered. Service Provider should be registered in advance";
                log.error(message);
                String errorResp = SAMLSSOUtil
                        .buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, message, null);
                validationResponse.setResponse(errorResp);
                validationResponse.setValid(false);
                return validationResponse;
            }


            SAMLSSOUtil.setIssuerWithQualifierInThreadLocal(validationResponse.getIssuer());

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
}
