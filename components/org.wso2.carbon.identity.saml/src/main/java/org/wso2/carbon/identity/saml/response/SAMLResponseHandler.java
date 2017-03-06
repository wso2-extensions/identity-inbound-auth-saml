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
package org.wso2.carbon.identity.saml.response;

import org.apache.xml.security.utils.EncryptionConstants;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.xml.security.x509.X509Credential;
import org.slf4j.Logger;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.gateway.api.exception.GatewayException;
import org.wso2.carbon.identity.gateway.api.exception.GatewayRuntimeException;
import org.wso2.carbon.identity.gateway.common.model.sp.ResponseBuilderConfig;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.exception.AuthenticationHandlerException;
import org.wso2.carbon.identity.gateway.exception.ResponseHandlerException;
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.gateway.handler.response.AbstractResponseHandler;
import org.wso2.carbon.identity.saml.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.saml.builders.assertion.DefaultSAMLAssertionBuilder;
import org.wso2.carbon.identity.saml.builders.assertion.SAMLAssertionBuilder;
import org.wso2.carbon.identity.saml.builders.encryption.DefaultSSOEncrypter;
import org.wso2.carbon.identity.saml.builders.encryption.SSOEncrypter;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.exception.SAMLClientException;
import org.wso2.carbon.identity.saml.exception.SAMLRequestValidatorException;
import org.wso2.carbon.identity.saml.exception.SAMLRuntimeException;
import org.wso2.carbon.identity.saml.exception.SAMLServerException;
import org.wso2.carbon.identity.saml.model.SAMLConfigurations;
import org.wso2.carbon.identity.saml.model.SAMLResponseHandlerConfig;
import org.wso2.carbon.identity.saml.util.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;

public abstract class SAMLResponseHandler extends AbstractResponseHandler {

    private static Logger log = org.slf4j.LoggerFactory.getLogger(SAMLSPInitResponseHandler.class);

    @Override
    public GatewayHandlerResponse buildErrorResponse(AuthenticationContext authenticationContext, GatewayException e)
            throws
            ResponseHandlerException {
        try {
            setSAMLResponseHandlerConfigs(authenticationContext);
        } catch (AuthenticationHandlerException ex) {
            throw new ResponseHandlerException("Error while getting response handler configurations");
        }
        return GatewayHandlerResponse.REDIRECT;
    }

    @Override
    public GatewayHandlerResponse buildResponse(AuthenticationContext authenticationContext)
            throws ResponseHandlerException {
        try {
            setSAMLResponseHandlerConfigs(authenticationContext);
        } catch (AuthenticationHandlerException e) {
            throw new ResponseHandlerException("Error while getting response handler configurations");
        }
        return GatewayHandlerResponse.REDIRECT;
    }

    public Assertion buildSAMLAssertion(AuthenticationContext context, DateTime notOnOrAfter,
                                        String sessionId) throws IdentityException {
        SAMLAssertionBuilder samlAssertionBuilder = new DefaultSAMLAssertionBuilder();
        return samlAssertionBuilder.buildAssertion(context, notOnOrAfter, sessionId);
    }

    @Override
    public boolean canHandle(MessageContext messageContext, GatewayException exception) {
        if (canHandle(messageContext)) {
            if (exception instanceof SAMLRequestValidatorException || exception instanceof SAMLClientException ||
                exception instanceof SAMLServerException) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean canHandle(MessageContext messageContext, GatewayRuntimeException exception) {
        if (canHandle(messageContext)) {
            if (exception instanceof SAMLRuntimeException) {
                return true;
            }
        }
        return false;
    }

    public EncryptedAssertion setEncryptedAssertion(Assertion assertion, String encryptionAlgorithm,
                                                    String alias) throws IdentityException {
        SSOEncrypter ssoEncrypter = new DefaultSSOEncrypter();
        X509Credential cred = SAMLSSOUtil.getX509CredentialImplForTenant(alias);
        return ssoEncrypter.doEncryptedAssertion(assertion, cred, alias, encryptionAlgorithm);
    }

    public String setResponse(AuthenticationContext context, SAMLLoginResponse.SAMLLoginResponseBuilder
            builder) throws IdentityException {

        SAMLMessageContext messageContext = (SAMLMessageContext) context.getParameter(SAMLSSOConstants.SAMLContext);
        SAMLResponseHandlerConfig responseBuilderConfig = messageContext.getResponseHandlerConfig();
        if (log.isDebugEnabled()) {
            log.debug("Building SAML Response for the consumer '" + messageContext.getAssertionConsumerURL() + "'");
        }
        Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();
        response.setIssuer(SAMLSSOUtil.getIssuer());
        response.setID(SAMLSSOUtil.createID());
        if (!messageContext.isIdpInitSSO()) {
            response.setInResponseTo(messageContext.getId());
        }
        response.setDestination(messageContext.getAssertionConsumerURL());
        response.setStatus(buildStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
        response.setVersion(SAMLVersion.VERSION_20);
        DateTime issueInstant = new DateTime();
        DateTime notOnOrAfter = new DateTime(issueInstant.getMillis()
                                             + SAMLConfigurations.getInstance().getSamlResponseValidityPeriod() * 60
                                               * 1000L);
        response.setIssueInstant(issueInstant);
        //@TODO sessionHandling
        String sessionId = "";
        Assertion assertion = buildSAMLAssertion(context, notOnOrAfter, sessionId);

        if (responseBuilderConfig.isDoEnableEncryptedAssertion()) {

            String alias = responseBuilderConfig.getCertAlias();
            // TODO
            if (alias != null) {
                EncryptedAssertion encryptedAssertion = setEncryptedAssertion(assertion,
                                                                              EncryptionConstants
                                                                                      .ALGO_ID_BLOCKCIPHER_AES256,
                                                                              alias);
                response.getEncryptedAssertions().add(encryptedAssertion);
            }
        } else {
            response.getAssertions().add(assertion);
        }
        if (responseBuilderConfig.isDoSignResponse()) {
            SAMLSSOUtil.setSignature(response, responseBuilderConfig.getSigningAlgorithmUri(), responseBuilderConfig
                    .getDigestAlgorithmUri(), new SignKeyDataHolder());
        }
        builder.setResponse(response);
        String respString = SAMLSSOUtil.SAMLAssertion.encode(SAMLSSOUtil.SAMLAssertion.marshall(response));
        builder.setRespString(respString);
        builder.setAcsUrl(messageContext.getAssertionConsumerURL());
        builder.setRelayState(messageContext.getRelayState());
        addSessionKey(builder, context);
        return respString;
    }

    private Status buildStatus(String status, String statMsg) {

        Status stat = new StatusBuilder().buildObject();

        // Set the status code
        StatusCode statCode = new StatusCodeBuilder().buildObject();
        statCode.setValue(status);
        stat.setStatusCode(statCode);

        // Set the status Message
        if (statMsg != null) {
            StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
            statMesssage.setMessage(statMsg);
            stat.setStatusMessage(statMesssage);
        }

        return stat;
    }

    protected String getValidatorType() {
        return "SAML";
    }

    protected void setSAMLResponseHandlerConfigs(AuthenticationContext authenticationContext) throws
                                                                                              AuthenticationHandlerException {
        SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext
                .getParameter(SAMLSSOConstants.SAMLContext);
        ResponseBuilderConfig responseBuilderConfigs = getResponseBuilderConfigs(authenticationContext);
        SAMLResponseHandlerConfig samlResponseHandlerConfig = new SAMLResponseHandlerConfig(responseBuilderConfigs);
        messageContext.setResponseHandlerConfig(samlResponseHandlerConfig);
    }
}
