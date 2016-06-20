/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sso.samlnew.validators;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Subject;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.samlnew.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.samlnew.bean.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.samlnew.exception.SAML2ClientException;
import org.wso2.carbon.identity.sso.samlnew.util.SAMLSSOUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;


public class SPInitSSOAuthnRequestValidator implements SSOAuthnRequestValidator{

    private static Log log = LogFactory.getLog(SPInitSSOAuthnRequestValidator.class);
    private SAMLMessageContext messageContext;


    public SPInitSSOAuthnRequestValidator(SAMLMessageContext messageContext) throws IdentityException {
        this.messageContext = messageContext;
    }

    /**
     * Validates the authentication request according to SAML SSO Web Browser Specification
     *
     * @return boolean
     * @throws IdentityException
     */
    public boolean validate() throws IdentityException {

        try {
            AuthnRequest authnReq = messageContext.getAuthnRequest();
            Issuer issuer = authnReq.getIssuer();
            Subject subject = authnReq.getSubject();

            //@TODO Decide whether we want this
            //Validate the version
            if (!(SAMLVersion.VERSION_20.equals(authnReq.getVersion()))) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid version in the SAMLRequest" + authnReq.getVersion());
                }
                messageContext.setValid(false);
                throw SAML2ClientException.error(SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                                .VERSION_MISMATCH, "Invalid SAML Version " + "in Authentication Request. SAML Version" +
                                " should " +
                                "be equal to 2.0", authnReq.getAssertionConsumerServiceURL()), SAMLSSOConstants
                                .Notification.EXCEPTION_STATUS,
                        SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, authnReq.getAssertionConsumerServiceURL());
            }

            // Issuer MUST NOT be null
            if (StringUtils.isNotBlank(issuer.getValue())) {
                messageContext.setIssuer(issuer.getValue());
            } else if (StringUtils.isNotBlank(issuer.getSPProvidedID())) {
                messageContext.setIssuer(issuer.getSPProvidedID());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("SAML Request issuer validation failed. Issuer should not be empty");
                }
                messageContext.setValid(false);
                throw SAML2ClientException.error(SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                        .REQUESTOR_ERROR, "Issuer/ProviderName " + "should not be empty in the Authentication Request" +
                        ".", authnReq.getAssertionConsumerServiceURL()));
            }


            try {
                if (!SAMLSSOUtil.isSAMLIssuerExists(splitAppendedTenantDomain(issuer.getValue()),
                        SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
                    String message = "A Service Provider with the Issuer '" + issuer.getValue() + "' is not " +
                            "registered. Service Provider should be registered in " + "advance";
                    if (log.isDebugEnabled()) {
                        log.debug(message);
                    }
                    messageContext.setValid(false);
                    throw SAML2ClientException.error(SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                            .REQUESTOR_ERROR, message, null));
                }
            } catch (UserStoreException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error occurred while handling SAML2 SSO request", e);
                }
                messageContext.setValid(false);
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR,
                        "Error occurred while handling SAML2 SSO request", null);
                throw SAML2ClientException.error(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                        SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, null);
            } catch (IdentityException e) {
                log.error("Error when processing the authentication request!", e);
                messageContext.setValid(false);
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                        .IDENTITY_PROVIDER_ERROR, "Error when processing the authentication request", null);
                throw SAML2ClientException.error(errorResp, SAMLSSOConstants.Notification.EXCEPTION_STATUS,
                        SAMLSSOConstants.Notification.EXCEPTION_MESSAGE, null);
            }

            // Issuer Format attribute
            if ((StringUtils.isNotBlank(issuer.getFormat())) &&
                    !(issuer.getFormat().equals(SAMLSSOConstants.Attribute.ISSUER_FORMAT))) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Issuer Format attribute value " + issuer.getFormat());
                }
                messageContext.setValid(false);
                throw SAML2ClientException.error(SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                        .REQUESTOR_ERROR, "Issuer Format attribute" + " value is invalid", authnReq
                        .getAssertionConsumerServiceURL()));
            }

            SAMLSSOServiceProviderDO spDO = SAMLSSOUtil.getServiceProviderConfig(messageContext);
            if (spDO != null) {
                messageContext.setSamlssoServiceProviderDO(spDO);
            } else {
                String msg = "A Service Provider with the Issuer '" + messageContext.getIssuer() + "' is not " +
                        "registered." + " Service Provider should be registered in advance.";
                if (log.isDebugEnabled()) {
                    log.debug(msg);
                }
                messageContext.setValid(false);
                throw SAML2ClientException.error(SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                        .REQUESTOR_ERROR, msg, authnReq.getAssertionConsumerServiceURL()));
            }

            // Check for a Spoofing attack
            String acsUrl = authnReq.getAssertionConsumerServiceURL();
            boolean acsValidated = false;
            acsValidated = SAMLSSOUtil.validateACS(messageContext.getTenantDomain(), SAMLSSOUtil
                    .splitAppendedTenantDomain(messageContext.getIssuer()), authnReq
                    .getAssertionConsumerServiceURL());
            try {
                if (!acsValidated) {
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid ACS URL value " + acsUrl + " in the AuthnRequest message from " + spDO
                                .getIssuer() + "\n" + "Possibly an attempt for a spoofing attack from Provider " +
                                authnReq.getIssuer().getValue());
                    }
                    messageContext.setValid(false);
                    throw SAML2ClientException.error(SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                            .REQUESTOR_ERROR, "Invalid Assertion " + "Consumer Service URL in the Authentication " +
                            "Request" + ".", acsUrl));
                }
            } catch (IdentityException e) {
                //@TODO
                //Handle this exception
            }

            //TODO : Validate the NameID Format
            if (subject != null && subject.getNameID() != null) {
                messageContext.setSubject(subject.getNameID().getValue());
            }

            // subject confirmation should not exist
            if (subject != null && subject.getSubjectConfirmations() != null &&
                    !subject.getSubjectConfirmations().isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Request message. A Subject confirmation method found " + subject
                            .getSubjectConfirmations().get(0));
                }
                messageContext.setValid(false);
                throw SAML2ClientException.error(SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                        .REQUESTOR_ERROR, "Subject Confirmation " + "methods should NOT be in the request.", authnReq
                        .getAssertionConsumerServiceURL()));
            }
            messageContext.setValid(true);
            messageContext.addParameter(InboundConstants.ForceAuth, authnReq.isForceAuthn());
            messageContext.addParameter(InboundConstants.PassiveAuth, authnReq.isPassive());
            Integer index = authnReq.getAttributeConsumingServiceIndex();
            //according the spec, should be an unsigned short
            if (index != null && !(index < 1)) {
                messageContext.setAttributeConsumingServiceIndex(index);
            }
            if (log.isDebugEnabled()) {
                log.debug("Authentication Request Validation is successful.");
            }
            messageContext.setValid(true);
            return true;
        } catch (Exception e) {
            throw IdentityException.error("Error validating the authentication request", e);
        }
    }

    protected String splitAppendedTenantDomain(String issuer) throws UserStoreException, IdentityException {

        if(IdentityUtil.isBlank(SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
            if (issuer.contains("@")) {
                String tenantDomain = issuer.substring(issuer.lastIndexOf('@') + 1);
                issuer = issuer.substring(0, issuer.lastIndexOf('@'));
                if (StringUtils.isNotBlank(tenantDomain) && StringUtils.isNotBlank(issuer)) {
                    SAMLSSOUtil.setTenantDomainInThreadLocal(tenantDomain);
                    if (log.isDebugEnabled()) {
                        log.debug("Tenant Domain: " + tenantDomain + " & Issuer name: " + issuer + "has been " +
                                "split");
                    }
                }
            }
        }
        if(IdentityUtil.isBlank(SAMLSSOUtil.getTenantDomainFromThreadLocal())){
            SAMLSSOUtil.setTenantDomainInThreadLocal(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        }
        return issuer;
    }

}
