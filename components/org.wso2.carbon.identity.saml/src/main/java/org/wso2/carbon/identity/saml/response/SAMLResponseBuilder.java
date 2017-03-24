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
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.auth.saml2.common.X509CredentialImpl;
import org.wso2.carbon.identity.common.base.handler.AbstractMessageHandler;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.saml.bean.MessageContext;
import org.wso2.carbon.identity.saml.exception.SAML2SSOResponseBuilderException;
import org.wso2.carbon.identity.saml.model.Config;
import org.wso2.carbon.identity.saml.model.ResponseBuilderConfig;
import org.wso2.carbon.identity.saml.util.Utils;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * SPI to build a SAMLResponse.
 */
public class SAMLResponseBuilder extends AbstractMessageHandler {

    protected Response buildSAMLResponse(String subject, Set<Claim> claims, MessageContext messageContext,
                                         ResponseBuilderConfig config, AuthenticationContext context)
            throws SAML2SSOResponseBuilderException {

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

        buildAssertion(subject, claims, response, issueInstant, messageContext, config, context);

        if (config.signResponse()) {
            SAML2AuthUtils.setSignature(response, config.getSigningAlgorithmUri(), config
                    .getDigestAlgorithmUri(), true, SAML2AuthUtils.getServerCredentials());
        }

        return response;
    }

    protected Issuer getIssuer() {

        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setFormat(NameID.ENTITY);
        String idPEntityId = Config.getInstance().getIdpEntityId();
        issuer.setValue(idPEntityId);
        return issuer;
    }

    protected void buildAssertion(String subject, Set<Claim> claims, Response response, DateTime issueInstant,
                                  MessageContext messageContext, ResponseBuilderConfig config,
                                  AuthenticationContext context)
            throws SAML2SSOResponseBuilderException {

        DateTime notOnOrAfter = new DateTime(issueInstant.getMillis() + config.getNotOnOrAfterPeriod() * 60 * 1000L);
        DateTime currentTime = new DateTime();
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setID(SAML2AuthUtils.createID());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(getIssuer());
        assertion.setIssueInstant(currentTime);
        Subject subjectElem = new SubjectBuilder().buildObject();

        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setValue(subject);
        if (config.getNameIdFormat() != null) {
            nameId.setFormat(config.getNameIdFormat());
        } else {
            nameId.setFormat(NameIdentifier.EMAIL);
        }

        subjectElem.setNameID(nameId);

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
        subjectElem.getSubjectConfirmations().add(subjectConfirmation);

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
            subjectElem.getSubjectConfirmations().add(subjectConfirmation);
        }

        assertion.setSubject(subjectElem);

        AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
        authStmt.setAuthnInstant(new DateTime());

        AuthnContext authContext = new AuthnContextBuilder().buildObject();
        AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
        authCtxClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authContext.setAuthnContextClassRef(authCtxClassRef);
        authStmt.setAuthnContext(authContext);
        assertion.getAuthnStatements().add(authStmt);

        buildAttributeStatement(claims, assertion, messageContext, config, context);

        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder()
                .buildObject();
        Audience issuerAudience = new AudienceBuilder().buildObject();
        issuerAudience.setAudienceURI(messageContext.getIssuerWithDomain());
        audienceRestriction.getAudiences().add(issuerAudience);
        for (String requestedAudience : config.getRequestedAudiences()) {
            Audience audience = new AudienceBuilder().buildObject();
            audience.setAudienceURI(requestedAudience);
            audienceRestriction.getAudiences().add(audience);
        }
        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(currentTime);
        conditions.setNotOnOrAfter(notOnOrAfter);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);

        // signing has to be ideally done at transport binding level. encryption also will have to move there.

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

    protected void encryptAssertion(Response response, Assertion assertion, ResponseBuilderConfig config)
            throws SAML2SSOResponseBuilderException {

        if (!config.encryptAssertion()) {

            response.getAssertions().add(assertion);

        } else {

            String encodedCert = config.getEncryptionCertificate();
            if (StringUtils.isBlank(encodedCert)) {
                SAML2SSOResponseBuilderException ex =
                        new SAML2SSOResponseBuilderException(StatusCode.RESPONDER_URI,
                                                             "Encryption certificate is not configured.");
                ex.setInResponseTo(response.getID());
                ex.setAcsUrl(response.getDestination());
                throw ex;
            }
            Certificate certificate;
            try {
                certificate = Utils.decodeCertificate(encodedCert);
            } catch (CertificateException e) {
                SAML2SSOResponseBuilderException ex =
                        new SAML2SSOResponseBuilderException(StatusCode.RESPONDER_URI,
                                                             "Invalid encoded certificate: " + encodedCert);
                ex.setInResponseTo(response.getID());
                ex.setAcsUrl(response.getDestination());
                throw ex;
            }

            Credential symmetricCredential = null;
            try {
                symmetricCredential = SecurityHelper.getSimpleCredential(
                        SecurityHelper.generateSymmetricKey("http://www.w3.org/2001/04/xmlenc#aes256-cbc"));
            } catch (NoSuchAlgorithmException | KeyException e) {
                SAML2SSOResponseBuilderException ex =
                        new SAML2SSOResponseBuilderException(StatusCode.RESPONDER_URI,
                                                             "Error occurred while encrypting assertion.", e);
                ex.setInResponseTo(assertion.getID());
                ex.setAcsUrl(response.getDestination());
                throw ex;
            }

            EncryptionParameters encParams = new EncryptionParameters();
            encParams.setAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc");
            encParams.setEncryptionCredential(symmetricCredential);

            KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
            keyEncryptionParameters.setAlgorithm("http://www.w3.org/2001/04/xmlenc#rsa-1_5");
            keyEncryptionParameters.setEncryptionCredential(new X509CredentialImpl((X509Certificate) certificate));

            Encrypter encrypter = new Encrypter(encParams, keyEncryptionParameters);
            encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

            EncryptedAssertion encryptedAssertion = null;
            try {
                encryptedAssertion = encrypter.encrypt(assertion);
            } catch (EncryptionException e) {
                SAML2SSOResponseBuilderException ex =
                        new SAML2SSOResponseBuilderException(StatusCode.RESPONDER_URI,
                                                             "Error occurred while encrypting assertion.", e);
                ex.setInResponseTo(assertion.getID());
                ex.setAcsUrl(response.getDestination());
                throw ex;
            }

            response.getEncryptedAssertions().add(encryptedAssertion);
        }
    }

    protected void buildAttributeStatement(Set<Claim> claims, Assertion assertion, MessageContext messageContext,
                                           ResponseBuilderConfig config, AuthenticationContext context) {

        AttributeStatement attStmt = new AttributeStatementBuilder().buildObject();
        Iterator<Claim> iterator = claims.iterator();
        while (iterator.hasNext()) {
            Claim claim = iterator.next();
            String claimUri = claim.getClaimUri();
            String claimValue = claim.getValue();
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
        if (attStmt != null) {
            assertion.getAttributeStatements().add(attStmt);
        }
    }



    protected Response buildErrorResponse(String inResponseTo, String status, String message, String destination) {

        List<String> statusCodeList = new ArrayList();
        statusCodeList.add(status);
        return buildErrorResponse(inResponseTo, statusCodeList, message, destination);
    }

    protected Response buildErrorResponse(String inResponseToId, List<String> statusCodes, String statusMsg,
                                          String destination) {

        if (statusCodes == null || statusCodes.isEmpty()) {
            return null;
        }
        Response response = new ResponseBuilder().buildObject();
        response.setIssuer(getIssuer());
        Status status = new StatusBuilder().buildObject();
        StatusCode statusCode = null;
        for (String statCode : statusCodes) {
            statusCode = buildStatusCode(statCode, statusCode);
        }
        status.setStatusCode(statusCode);
        buildStatusMsg(status, statusMsg);
        response.setStatus(status);
        response.setVersion(SAMLVersion.VERSION_20);
        response.setID(SAML2AuthUtils.createID());
        if (StringUtils.isNotBlank(inResponseToId)) {
            response.setInResponseTo(inResponseToId);
        }
        if (destination != null) {
            response.setDestination(destination);
        }
        response.setIssueInstant(new DateTime());
        return response;
    }

    private StatusCode buildStatusCode(String parentStatusCode, StatusCode childStatusCode) {

        if (StringUtils.isBlank(parentStatusCode)) {
            return childStatusCode;
        }

        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue(parentStatusCode);

        if (childStatusCode != null) {
            statusCode.setStatusCode(childStatusCode);
            return statusCode;
        } else {
            return statusCode;
        }
    }

    private Status buildStatusMsg(Status status, String statusMsg) {

        if (statusMsg != null) {
            StatusMessage statusMesssage = new StatusMessageBuilder().buildObject();
            statusMesssage.setMessage(statusMsg);
            status.setStatusMessage(statusMesssage);
        }
        return status;
    }
}
