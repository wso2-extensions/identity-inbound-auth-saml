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
package org.wso2.carbon.identity.sso.samlnew.processor;


import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.Subject;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.samlnew.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.samlnew.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.samlnew.bean.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.samlnew.bean.message.request.SAMLIdentityRequest;
import org.wso2.carbon.identity.sso.samlnew.bean.message.response.SAMLResponse;
import org.wso2.carbon.identity.sso.samlnew.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.samlnew.util.SAMLSSOUtil;

import org.opensaml.xml.XMLObject;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.HashMap;

public class SPInitSSOAuthnRequestProcessor extends IdentityProcessor {
    private static Log log = LogFactory.getLog(SPInitSSOAuthnRequestProcessor.class);
    private String relyingParty;

    @Override
    public String getName() {
        return "SPInitSSOAuthnRequestProcessor";
    }

    public int getPriority() {
        return 1;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("identity",false,false);
    }

    @Override
    public String getRelyingPartyId() {
        return this.relyingParty;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if (identityRequest instanceof SAMLIdentityRequest && ((SAMLIdentityRequest) identityRequest).getSamlRequest
                () != null) {
            return true;
        }
        return false;
    }

    @Override
    public FrameworkLoginResponse.FrameworkLoginResponseBuilder process(IdentityRequest identityRequest) throws
            FrameworkException {
        SAMLMessageContext messageContext = new SAMLMessageContext((SAMLIdentityRequest) identityRequest, new
                HashMap<String, String>());
        try {
            if(!validateSPInitSSORequest(messageContext)) {
                throw new FrameworkException("Validation Failed");
            }
        } catch (IdentityException e) {
            throw new FrameworkException("ExceptionThrown");
        }
        FrameworkLoginResponse.FrameworkLoginResponseBuilder builder = buildResponseForFrameworkLogin(messageContext);
        return builder;
    }


    protected boolean validateSPInitSSORequest(SAMLMessageContext messageContext) throws IdentityException {
        SAMLIdentityRequest identityRequest = messageContext.getRequest();
        XMLObject request = SAMLSSOUtil.unmarshall(SAMLSSOUtil.decode(identityRequest.getSamlRequest()));
        if (request instanceof AuthnRequest) {
            messageContext.setIdpInitSSO(false);
            messageContext.setAuthnRequest((AuthnRequest)request);
            return validateAuthnRequest(messageContext);
        }
        return false;
//        else if (request instanceof LogoutRequest) {
//
//        }
    }

    protected String splitAppendedTenantDomain(String issuer) throws UserStoreException, IdentityException {

        if (IdentityUtil.isBlank(SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
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
        if (IdentityUtil.isBlank(SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
            SAMLSSOUtil.setTenantDomainInThreadLocal(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        }
        return issuer;
    }

    private boolean validateAuthnRequest(SAMLMessageContext messageContext) throws IdentityException {
        try {
            AuthnRequest authnReq = messageContext.getAuthnRequest();
            Issuer issuer = authnReq.getIssuer();
            Subject subject = authnReq.getSubject();
            this.relyingParty = issuer.getValue();
            boolean isLoginRequired = messageContext.getRequest().isLoginRequired();
            messageContext.addParameter(InboundConstants.ForceAuth, isLoginRequired);
            boolean isPromptNone = messageContext.getRequest().isPromptNone();
            messageContext.addParameter(InboundConstants.PassiveAuth, isPromptNone);
            //@TODO Decide whether we want this

            // Validate the version
//            if (!(SAMLVersion.VERSION_20.equals(authnReq.getVersion()))) {
//                String errorResp = SAMLSSOUtil.buildErrorResponse(
//                        SAMLSSOConstants.StatusCodes.VERSION_MISMATCH,
//                        "Invalid SAML Version in Authentication Request. SAML Version should be equal to 2.0",
//                        authnReq.getAssertionConsumerServiceURL());
//                if (log.isDebugEnabled()) {
//                    log.debug("Invalid version in the SAMLRequest" + authnReq.getVersion());
//                }
//                validationResponse.setResponse(errorResp);
//                validationResponse.setValid(false);
//                return validationResponse;
//            }

            // Issuer MUST NOT be null
            if (StringUtils.isNotBlank(issuer.getValue())) {
            } else if (StringUtils.isNotBlank(issuer.getSPProvidedID())) {
            } else {
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "Issuer/ProviderName should not be empty in the Authentication Request.", authnReq
                                .getAssertionConsumerServiceURL(), messageContext);
                log.debug("SAML Request issuer validation failed. Issuer should not be empty");
                return false;
            }

            if (!SAMLSSOUtil.isSAMLIssuerExists(splitAppendedTenantDomain(issuer.getValue()),
                    SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
                String message = "A Service Provider with the Issuer '" + issuer.getValue() + "' is not " +
                        "registered. Service Provider should be registered in " + "advance";
                log.error(message);
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        message, null, messageContext);
                return false;
            }

            // Issuer Format attribute
            if ((StringUtils.isNotBlank(issuer.getFormat())) &&
                    !(issuer.getFormat().equals(SAMLSSOConstants.Attribute.ISSUER_FORMAT))) {
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "Issuer Format attribute value is invalid", authnReq.getAssertionConsumerServiceURL(),
                        messageContext);
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Issuer Format attribute value " + issuer.getFormat());
                }
                return false;
            }

            //TODO : REMOVE THIS UNNECESSARY CHECK
            // set the custom login page URL and ACS URL if available
            SSOServiceProviderConfigManager spConfigManager = SSOServiceProviderConfigManager.getInstance();
            SAMLSSOServiceProviderDO spDO = spConfigManager.getServiceProvider(issuer.getValue());
            String spAcsUrl = null;
            if (spDO != null) {
                //validationResponse.setLoginPageURL(spDO.getLoginPageURL());
                spAcsUrl = spDO.getAssertionConsumerUrl();
            }

            // Check for a Spoofing attack
            String acsUrl = authnReq.getAssertionConsumerServiceURL();
            if (StringUtils.isNotBlank(spAcsUrl) && StringUtils.isNotBlank(acsUrl) && !acsUrl.equals(spAcsUrl)) {
                log.error("Invalid ACS URL value " + acsUrl + " in the AuthnRequest message from " +
                        spDO.getIssuer() + "\n" +
                        "Possibly an attempt for a spoofing attack from Provider " +
                        authnReq.getIssuer().getValue());

                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "Invalid Assertion Consumer Service URL in the Authentication Request.", acsUrl,
                        messageContext);
//                validationResponse.setResponse(errorResp);
//                validationResponse.setValid(false);
                return false;
            }

            //TODO : Validate the NameID Format
            if (subject != null && subject.getNameID() != null) {
                //validationResponse.setSubject(subject.getNameID().getValue());
            }

            // subject confirmation should not exist
            if (subject != null && subject.getSubjectConfirmations() != null &&
                    !subject.getSubjectConfirmations().isEmpty()) {
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "Subject Confirmation methods should NOT be in the request.", authnReq
                                .getAssertionConsumerServiceURL(), messageContext);
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Request message. A Subject confirmation method found " + subject
                            .getSubjectConfirmations().get(0));
                }
                return false;
            }
            Integer index = authnReq.getAttributeConsumingServiceIndex();
            if (index != null && !(index < 1)) {              //according the spec, should be an unsigned short
                //validationResponse.setAttributeConsumingServiceIndex(index);
            }
            if (log.isDebugEnabled()) {
                log.debug("Authentication Request Validation is successful.");
            }
            return true;
        } catch (Exception e) {
            throw IdentityException.error("Error validating the authentication request", e);
        }

    }


    private SAMLResponse.SAMLResponseBuilder buildSAMLResponse() {
        return null;
    }

}
