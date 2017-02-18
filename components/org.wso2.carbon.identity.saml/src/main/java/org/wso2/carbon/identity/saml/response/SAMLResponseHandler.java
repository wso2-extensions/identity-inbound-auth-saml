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
import org.wso2.carbon.identity.gateway.api.response.FrameworkHandlerResponse;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.processor.handler.authentication.AuthenticationHandlerException;
import org.wso2.carbon.identity.gateway.processor.handler.response.AbstractResponseHandler;
import org.wso2.carbon.identity.gateway.processor.handler.response.ResponseException;
import org.wso2.carbon.identity.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.bean.SAMLConfigurations;
import org.wso2.carbon.identity.saml.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.saml.builders.assertion.DefaultSAMLAssertionBuilder;
import org.wso2.carbon.identity.saml.builders.assertion.SAMLAssertionBuilder;
import org.wso2.carbon.identity.saml.builders.encryption.DefaultSSOEncrypter;
import org.wso2.carbon.identity.saml.builders.encryption.SSOEncrypter;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.saml.wrapper.SAMLResponseHandlerConfig;

import java.util.Properties;

abstract public class SAMLResponseHandler extends AbstractResponseHandler {

    private static Logger log = org.slf4j.LoggerFactory.getLogger(SAMLSPInitResponseHandler.class);

    @Override
    public FrameworkHandlerResponse buildErrorResponse(AuthenticationContext authenticationContext, IdentityException e) throws
            ResponseException {
        try {
            setSAMLResponseHandlerConfigs(authenticationContext);
        } catch (AuthenticationHandlerException ex) {
            throw new ResponseException("Error while getting response handler configurations");
        }
        return FrameworkHandlerResponse.REDIRECT;
    }

    @Override
    public FrameworkHandlerResponse buildResponse(AuthenticationContext authenticationContext) throws ResponseException {
        try {
            setSAMLResponseHandlerConfigs(authenticationContext);
        } catch (AuthenticationHandlerException e) {
            throw new ResponseException("Error while getting response handler configurations");
        }
        return FrameworkHandlerResponse.REDIRECT;
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
                + SAMLConfigurations.getInstance().getSamlResponseValidityPeriod() * 60 * 1000L);
        response.setIssueInstant(issueInstant);
        //@TODO sessionHandling
        String sessionId = "";
        Assertion assertion = buildSAMLAssertion(context, notOnOrAfter, sessionId);

        if (responseBuilderConfig.isDoEnableEncryptedAssertion()) {

            String domainName = messageContext.getTenantDomain();
            String alias = responseBuilderConfig.getCertAlias();
            // TODO
            if (alias != null) {
                EncryptedAssertion encryptedAssertion = setEncryptedAssertion(assertion,
                        EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256, alias, domainName);
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
        String respString = SAMLSSOUtil.encode(SAMLSSOUtil.marshall(response));
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

    public EncryptedAssertion setEncryptedAssertion(Assertion assertion, String encryptionAlgorithm,
                                                    String alias, String domainName) throws IdentityException {
        SAMLSSOUtil.doBootstrap();

        SSOEncrypter ssoEncrypter = new DefaultSSOEncrypter();
        X509Credential cred = SAMLSSOUtil.getX509CredentialImplForTenant(domainName, alias);
        return ssoEncrypter.doEncryptedAssertion(assertion, cred, alias, encryptionAlgorithm);
    }

    public Assertion buildSAMLAssertion(AuthenticationContext context, DateTime notOnOrAfter,
                                        String sessionId) throws IdentityException {
        SAMLSSOUtil.doBootstrap();
        SAMLAssertionBuilder samlAssertionBuilder = new DefaultSAMLAssertionBuilder();
        return samlAssertionBuilder.buildAssertion(context, notOnOrAfter, sessionId);

    }

    protected String getValidatorType() {
        return "SAML";
    }

    protected void setSAMLResponseHandlerConfigs(AuthenticationContext authenticationContext) throws
            AuthenticationHandlerException {
        SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext.getParameter(SAMLSSOConstants.SAMLContext);
        Properties samlValidatorProperties = getResponseBuilderConfigs(authenticationContext);
        SAMLResponseHandlerConfig samlResponseHandlerConfig = new SAMLResponseHandlerConfig(samlValidatorProperties);
        messageContext.setResponseHandlerConfig(samlResponseHandlerConfig);
    }
}
