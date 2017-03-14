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

import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.utils.EncryptionConstants;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.auth.saml2.common.X509CredentialImpl;
import org.wso2.carbon.identity.common.base.handler.AbstractMessageHandler;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.saml.bean.MessageContext;
import org.wso2.carbon.identity.saml.exception.SAML2SSORuntimeException;
import org.wso2.carbon.identity.saml.exception.SAML2SSOServerException;
import org.wso2.carbon.identity.saml.model.Config;
import org.wso2.carbon.identity.saml.model.ResponseBuilderConfig;
import org.wso2.carbon.identity.saml.util.Utils;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Map;

/**
 * SPI to build a SAML2 Response.
 */
public class SAMLResponseBuilder extends AbstractMessageHandler {

    private static Logger logger = LoggerFactory.getLogger(SAMLResponseBuilder.class);

    protected Response buildSAMLResponse(MessageContext messageContext, ResponseBuilderConfig config,
                                         AuthenticationContext context) throws SAML2SSOServerException {

        Response response = new ResponseBuilder().buildObject();
        response.setIssuer(getIssuer());
        response.setID(SAML2AuthUtils.createID());
        if (!messageContext.isIdpInitSSO()) {
            response.setInResponseTo(messageContext.getId());
        }
        response.setDestination(messageContext.getAssertionConsumerURL());
        buildStatus(response, StatusCode.SUCCESS_URI, null);
        response.setVersion(SAMLVersion.VERSION_20);
        DateTime issueInstant = new DateTime();
        response.setIssueInstant(issueInstant);

        buildAssertion(response, issueInstant, messageContext, config, context);

        if (config.signResponse()) {
            SAML2AuthUtils.setSignature(response, config.getSigningAlgorithmUri(), config
                    .getDigestAlgorithmUri(), true, SAML2AuthUtils.getServerCredentials());
        }

        return response;
    }

    public Issuer getIssuer() {

        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setFormat(NameID.ENTITY);
        String idPEntityId = Config.getInstance().getIdpEntityId();
        issuer.setValue(idPEntityId);
        return issuer;
    }

    protected void buildAssertion(Response response, DateTime issueInstant, MessageContext messageContext,
                                  ResponseBuilderConfig config, AuthenticationContext context)
            throws SAML2SSOServerException {

        DateTime notOnOrAfter = new DateTime(issueInstant.getMillis() + config.getNotOnOrAfterPeriod() * 60 * 1000L);
        DateTime currentTime = new DateTime();
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setID(SAML2AuthUtils.createID());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(getIssuer());
        assertion.setIssueInstant(currentTime);
        Subject subject = new SubjectBuilder().buildObject();

        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setValue(Utils.getSubject(context));
        if (config.getNameIdFormat() != null) {
            nameId.setFormat(config.getNameIdFormat());
        } else {
            nameId.setFormat(NameIdentifier.EMAIL);
        }

        subject.setNameID(nameId);

        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder()
                .buildObject();
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData scData = new SubjectConfirmationDataBuilder().buildObject();
        scData.setRecipient(messageContext.getAssertionConsumerURL());
        scData.setNotOnOrAfter(notOnOrAfter);
        if (!messageContext.isIdpInitSSO()) {
            scData.setInResponseTo(messageContext.getId());
        }
        subjectConfirmation.setSubjectConfirmationData(scData);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        if (config.getRequestedRecipients() != null && config.getRequestedRecipients().length > 0) {
            for (String recipient : config.getRequestedRecipients()) {
                subjectConfirmation = new SubjectConfirmationBuilder()
                        .buildObject();
                subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
                scData = new SubjectConfirmationDataBuilder().buildObject();
                scData.setRecipient(recipient);
                scData.setNotOnOrAfter(notOnOrAfter);
                if (!messageContext.isIdpInitSSO()) {
                    scData.setInResponseTo(messageContext.getId());
                }
                subjectConfirmation.setSubjectConfirmationData(scData);
                subject.getSubjectConfirmations().add(subjectConfirmation);
            }
        }

        assertion.setSubject(subject);

        AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
        authStmt.setAuthnInstant(new DateTime());

        AuthnContext authContext = new AuthnContextBuilder().buildObject();
        AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
        authCtxClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authContext.setAuthnContextClassRef(authCtxClassRef);
        authStmt.setAuthnContext(authContext);
        assertion.getAuthnStatements().add(authStmt);

        /*
        * If <AttributeConsumingServiceIndex> element is in the <AuthnRequest> and according to
        * the spec 2.0 the subject MUST be in the assertion
        */
        Map<String, String> claims = Utils.getAttributes(context);
        if (claims != null && !claims.isEmpty()) {
            AttributeStatement attrStmt = buildAttributeStatement(claims);
            if (attrStmt != null) {
                assertion.getAttributeStatements().add(attrStmt);
            }
        }

        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder()
                .buildObject();
        Audience issuerAudience = new AudienceBuilder().buildObject();
        issuerAudience.setAudienceURI(messageContext.getIssuerWithDomain());
        audienceRestriction.getAudiences().add(issuerAudience);
        if (config.getRequestedAudiences() != null) {
            for (String requestedAudience : config.getRequestedAudiences()) {
                Audience audience = new AudienceBuilder().buildObject();
                audience.setAudienceURI(requestedAudience);
                audienceRestriction.getAudiences().add(audience);
            }
        }
        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(currentTime);
        conditions.setNotOnOrAfter(notOnOrAfter);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);

        SAML2AuthUtils.setSignature(assertion, config.getSigningAlgorithmUri(), config.getDigestAlgorithmUri(),
                                        true, SAML2AuthUtils.getServerCredentials());

        encryptAssertion(response, assertion, config);
    }

    protected void buildStatus(Response response, String statusCode, String statusMessage) {

        Status status = new StatusBuilder().buildObject();

        StatusCode statusCodeObject = new StatusCodeBuilder().buildObject();
        statusCodeObject.setValue(statusCode);
        status.setStatusCode(statusCodeObject);

        if (statusMessage != null) {
            StatusMessage statusMessageObject = new StatusMessageBuilder().buildObject();
            statusMessageObject.setMessage(statusMessage);
            status.setStatusMessage(statusMessageObject);
        }

        response.setStatus(status);
    }

    public void encryptAssertion(Response response, Assertion assertion, ResponseBuilderConfig config)
            throws SAML2SSOServerException {

        if (!config.encryptAssertion()) {

            response.getAssertions().add(assertion);

        } else {

            String encodedCert = config.getEncryptionCertificate();
            if (StringUtils.isBlank(encodedCert)) {
                throw new SAML2SSOServerException("", "Encryption certificate is not configured.");
            }
            Certificate certificate;
            try {
                certificate = Utils.decodeCertificate(encodedCert);
            } catch (CertificateException e) {
                throw new SAML2SSOServerException("", "Invalid encoded certificate: " + encodedCert);
            }

            Credential symmetricCredential = null;
            try {
                symmetricCredential = SecurityHelper.getSimpleCredential(
                        SecurityHelper.generateSymmetricKey(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256));
            } catch (NoSuchAlgorithmException | KeyException e) {
                throw new SAML2SSORuntimeException("Error occurred while encrypting Assertion.");
            }

            EncryptionParameters encParams = new EncryptionParameters();
            encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);
            encParams.setEncryptionCredential(symmetricCredential);

            KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
            keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);
            keyEncryptionParameters.setEncryptionCredential(new X509CredentialImpl((X509Certificate) certificate));

            Encrypter encrypter = new Encrypter(encParams, keyEncryptionParameters);
            encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

            EncryptedAssertion encryptedAssertion = null;
            try {
                encryptedAssertion = encrypter.encrypt(assertion);
            } catch (EncryptionException e) {
                throw new SAML2SSORuntimeException("Error occurred while encrypting Assertion.");
            }

            response.getEncryptedAssertions().add(encryptedAssertion);
        }
    }

    private AttributeStatement buildAttributeStatement(Map<String, String> claims) {

        AttributeStatement attStmt = new AttributeStatementBuilder().buildObject();
        Iterator<Map.Entry<String, String>> iterator = claims.entrySet().iterator();
        boolean atLeastOneNotEmpty = false;
        for (int i = 0; i < claims.size(); i++) {
            Map.Entry<String, String> claimEntry = iterator.next();
            String claimUri = claimEntry.getKey();
            String claimValue = claimEntry.getValue();
            if (claimUri != null && !claimUri.trim().isEmpty() && claimValue != null && !claimValue.trim().isEmpty()) {
                atLeastOneNotEmpty = true;
                Attribute attribute = new AttributeBuilder().buildObject();
                attribute.setName(claimUri);
                //setting NAMEFORMAT attribute value to basic attribute profile
                attribute.setNameFormat(Attribute.BASIC);
                // look
                // https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUsrManJavaAnyTypes
                XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().
                        getBuilder(XSString.TYPE_NAME);
                XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString
                        .TYPE_NAME);
                stringValue.setValue(claimValue);
                attribute.getAttributeValues().add(stringValue);
                attStmt.getAttributes().add(attribute);
            }
        }
        if (atLeastOneNotEmpty) {
            return attStmt;
        } else {
            return null;
        }
    }
}
