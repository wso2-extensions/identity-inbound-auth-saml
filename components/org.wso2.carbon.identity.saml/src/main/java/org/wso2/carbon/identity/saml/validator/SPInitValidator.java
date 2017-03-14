/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.saml.validator;

import org.apache.commons.lang.StringUtils;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.saml.bean.MessageContext;
import org.wso2.carbon.identity.saml.exception.SAML2SSORequestValidationException;
import org.wso2.carbon.identity.saml.exception.SAML2SSOServerException;
import org.wso2.carbon.identity.saml.model.Config;
import org.wso2.carbon.identity.saml.model.RequestValidatorConfig;
import org.wso2.carbon.identity.saml.request.SPInitRequest;
import org.wso2.carbon.identity.saml.util.AuthnReqSigUtil;

import java.util.List;

/**
 * SP Initiated SAML2 SSO Inbound Request Validator.
 */
public class SPInitValidator extends SAML2SSOValidator {

    private static Logger logger = LoggerFactory.getLogger(SPInitValidator.class);

    @Override
    public boolean canHandle(org.wso2.carbon.identity.common.base.message.MessageContext messageContext) {
        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getInitialAuthenticationRequest() instanceof SPInitRequest) {
                return true;
            }
        }
        return false;
    }

    @Override
    public int getPriority(org.wso2.carbon.identity.common.base.message.MessageContext messageContext) {
        return 10;
    }

    protected MessageContext createInboundMessageContext(AuthenticationContext authenticationContext)
            throws SAML2SSORequestValidationException {

        MessageContext messageContext = super.createInboundMessageContext(authenticationContext);
        SPInitRequest spInitRequest = ((SPInitRequest) messageContext.getInitialAuthenticationRequest());
        AuthnRequest authnRequest = spInitRequest.getAuthnRequest();
        Issuer issuer = authnRequest.getIssuer();
        if (issuer == null) {
            throw new SAML2SSORequestValidationException("", "");
        }
        if (StringUtils.isNotBlank(issuer.getValue())) {
            authenticationContext.setUniqueId(issuer.getValue());
        } else if (StringUtils.isNotBlank(issuer.getSPProvidedID())) {
            authenticationContext.setUniqueId(issuer.getValue());
        }

        org.wso2.carbon.identity.gateway.common.model.sp.RequestValidatorConfig validatorConfig =
                getValidatorConfig(authenticationContext);
        RequestValidatorConfig requestValidatorConfig = new RequestValidatorConfig(validatorConfig);
        messageContext.setRequestValidatorConfig(requestValidatorConfig);
        return messageContext;
    }

    @Override
    public GatewayHandlerResponse validate(AuthenticationContext authenticationContext)
            throws SAML2SSORequestValidationException {

        MessageContext messageContext = createInboundMessageContext(authenticationContext);
        SPInitRequest spInitRequest = (SPInitRequest) messageContext.getInitialAuthenticationRequest();
        AuthnRequest authnRequest = spInitRequest.getAuthnRequest();

        messageContext.setSPEntityId(messageContext.getUniqueId());
        messageContext.setDestination(authnRequest.getDestination());
        messageContext.setId((authnRequest).getID());
        messageContext.setAssertionConsumerUrl(authnRequest.getAssertionConsumerServiceURL());
        messageContext.setPassive(authnRequest.isPassive());
        messageContext.setForce(authnRequest.isForceAuthn());

        try {
            validateAuthnRequest(authnRequest, messageContext);
        } catch (SAML2SSOServerException e) {
            // shouldn't we throw GatewayServerException from validation handler. Only in Request factories we may
            // not throw server exception
        }

        return new GatewayHandlerResponse();

    }

    protected void validateAuthnRequest(AuthnRequest authnReq, MessageContext messageContext)
            throws SAML2SSORequestValidationException, SAML2SSOServerException {

        String appName = messageContext.getServiceProvider().getName();

        if (!(SAMLVersion.VERSION_20.equals(authnReq.getVersion()))) {
            throw new SAML2SSORequestValidationException(StatusCode.VERSION_MISMATCH_URI,
                                                         "Invalid SAML Version in AuthnRequest. SAML Version should " +
                                                         "be equal to 2.0.");
        }

        Issuer issuer = authnReq.getIssuer();

        if (StringUtils.isNotBlank(issuer.getFormat()) && !NameID.ENTITY.equals(issuer.getFormat())) {
            if (logger.isDebugEnabled()) {
                logger.debug("Invalid Issuer Format attribute value " + issuer.getFormat());
            }
            throw new SAML2SSORequestValidationException(StatusCode.REQUESTER_URI, "Invalid Issuer Format attribute " +
                                                                                   "value.");
        }

        RequestValidatorConfig requestValidatorConfig = messageContext.getRequestValidatorConfig();
        validateACS(authnReq.getAssertionConsumerServiceURL(), requestValidatorConfig);

        messageContext.setForce(authnReq.isForceAuthn());
        messageContext.setPassive(authnReq.isPassive());

        // TODO: Validate the NameID Format
        Subject subject = authnReq.getSubject();
        if (subject != null && subject.getNameID() != null &&
            StringUtils.isNotBlank(subject.getNameID().getValue())) {
            messageContext.setSubject(subject.getNameID().getValue());
        }

        // subject confirmation should not exist
        if (subject != null && subject.getSubjectConfirmations() != null &&
            !subject.getSubjectConfirmations().isEmpty()) {
            if (logger.isDebugEnabled()) {
                logger.debug("Invalid Request message. A Subject confirmation method found " + subject
                        .getSubjectConfirmations().get(0));
            }
            throw new SAML2SSORequestValidationException(StatusCode.REQUESTER_URI,
                                                         "Invalid Request message. A Subject confirmation method " +
                                                         "found " + subject.getSubjectConfirmations().get(0));
        }

        Integer index = authnReq.getAttributeConsumingServiceIndex();
        //according the spec, should be an unsigned short
        if (index != null && !(index < 1)) {
            messageContext.setAttributeConsumingServiceIndex(index);
        }

        // Validate the assertion consumer url, only if request is not signed.
        if (requestValidatorConfig.isRequireSignatureValidation()) {

            List<String> idpUrlSet = Config.getInstance().getDestinationUrls();

            if (messageContext.getDestination() == null || !idpUrlSet.contains(messageContext.getDestination())) {
                String msg = "Destination validation for AuthnRequest failed. " + "Received: [" +
                             messageContext.getDestination() + "]." + " Expected one in the list: [" + StringUtils
                                     .join(idpUrlSet, ',') + "]";
                throw new SAML2SSORequestValidationException(StatusCode.REQUESTER_URI, msg);
            }

            // validateAuthnRequest the signature
            boolean isSignatureValid = AuthnReqSigUtil.validateAuthnRequestSignature(authnReq,
                                                                                     messageContext,
                                                                                     requestValidatorConfig);

            if (!isSignatureValid) {
                String msg = "Signature validation for AuthnRequest failed.";
                throw new SAML2SSORequestValidationException(StatusCode.REQUESTER_URI, msg);
            }

        } else {

            String acsUrl = messageContext.getAssertionConsumerURL();
            if (StringUtils.isBlank(acsUrl) || !requestValidatorConfig.getAssertionConsumerUrlList()
                    .contains(acsUrl)) {
                throw new SAML2SSORequestValidationException(StatusCode.REQUESTER_URI,
                                                             "Invalid Assertion Consumer URL value '" + acsUrl + "' " +
                                                             "in the AuthnRequest message from '" + appName);
            }
        }
    }

    protected void validateACS(String requestedACSUrl,
                                      RequestValidatorConfig requestValidatorConfig)
            throws SAML2SSORequestValidationException {

        if (!requestValidatorConfig.getAssertionConsumerUrlList().contains(requestedACSUrl)) {
            throw new SAML2SSORequestValidationException(StatusCode.REQUESTER_URI, "Invalid Assertion Consumer " +
                                                                                    "Service URL in the AuthnRequest " +
                                                                                    "message.");
        }
    }
}
