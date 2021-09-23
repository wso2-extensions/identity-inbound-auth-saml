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
package org.wso2.carbon.identity.sso.saml.builders.assertion;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationContextProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.builders.AuthenticatingAuthorityImpl;
import org.wso2.carbon.identity.sso.saml.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

public class DefaultSAMLAssertionBuilder implements SAMLAssertionBuilder {

    private static final Log log = LogFactory.getLog(DefaultSAMLAssertionBuilder.class);

    private String userAttributeSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;

    @Override
    public void init() throws IdentityException {
        //Overridden method, no need to implement the body
    }

    @Override
    public Assertion buildAssertion(SAMLSSOAuthnReqDTO authReqDTO, DateTime notOnOrAfter, String sessionId) throws IdentityException {
        try {
            DateTime currentTime = new DateTime();
            Assertion samlAssertion = new AssertionBuilder().buildObject();

            this.setBasicInfo(samlAssertion, currentTime);

            this.setSubject(authReqDTO, notOnOrAfter, samlAssertion);

            this.addAuthStatement(authReqDTO, sessionId, samlAssertion);
            /*
                * If <AttributeConsumingServiceIndex> element is in the <AuthnRequest> and according to
                * the spec 2.0 the subject MUST be in the assertion
                */

            this.addAttributeStatements(authReqDTO, samlAssertion);

            this.setConditions(authReqDTO, currentTime, notOnOrAfter, samlAssertion);

            this.setSignature(authReqDTO, samlAssertion);

            return samlAssertion;

        } catch (Exception e) {
            log.error("Error when reading claim values for generating SAML Response", e);
            throw IdentityException.error(
                    "Error when reading claim values for generating SAML Response", e);
        }
    }
    protected void setBasicInfo(Assertion samlAssertion, DateTime currentTime)throws IdentityException{
        samlAssertion.setID(SAMLSSOUtil.createID());
        samlAssertion.setVersion(SAMLVersion.VERSION_20);
        samlAssertion.setIssuer(SAMLSSOUtil.getIssuer());
        samlAssertion.setIssueInstant(currentTime);
    }

    protected  void setNameId(SAMLSSOAuthnReqDTO authReqDTO, Subject subject){
        NameID nameId = new NameIDBuilder().buildObject();

        nameId.setValue(authReqDTO.getUser().getAuthenticatedSubjectIdentifier());
        if (authReqDTO.getNameIDFormat() != null) {
            nameId.setFormat(authReqDTO.getNameIDFormat());
        } else {
            nameId.setFormat(NameIdentifier.UNSPECIFIED);
        }
        subject.setNameID(nameId);
    }

    protected void addSubjectConfirmation(SAMLSSOAuthnReqDTO authReqDTO, DateTime notOnOrAfter, Subject subject ){
        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder()
                .buildObject();
        subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);
        SubjectConfirmationData scData = new SubjectConfirmationDataBuilder().buildObject();
        scData.setRecipient(authReqDTO.getAssertionConsumerURL());
        scData.setNotOnOrAfter(notOnOrAfter);
        if (!authReqDTO.isIdPInitSSOEnabled()) {
            scData.setInResponseTo(authReqDTO.getId());
        }
        subjectConfirmation.setSubjectConfirmationData(scData);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        if (authReqDTO.getRequestedRecipients() != null && authReqDTO.getRequestedRecipients().length > 0) {
            for (String recipient : authReqDTO.getRequestedRecipients()) {
                subjectConfirmation = new SubjectConfirmationBuilder()
                        .buildObject();
                subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);
                scData = new SubjectConfirmationDataBuilder().buildObject();
                scData.setRecipient(recipient);
                scData.setNotOnOrAfter(notOnOrAfter);
                if (!authReqDTO.isIdPInitSSOEnabled()) {
                    scData.setInResponseTo(authReqDTO.getId());
                }
                subjectConfirmation.setSubjectConfirmationData(scData);
                subject.getSubjectConfirmations().add(subjectConfirmation);
            }
        }
    }

    protected void setSubject (SAMLSSOAuthnReqDTO authReqDTO, DateTime notOnOrAfter, Assertion samlAssertion){
        Subject subject = new SubjectBuilder().buildObject();

        this.setNameId(authReqDTO, subject);

        this.addSubjectConfirmation(authReqDTO,notOnOrAfter,subject);

        samlAssertion.setSubject(subject);
    }


    protected void setSignature(SAMLSSOAuthnReqDTO authReqDTO, Assertion samlAssertion) throws IdentityException{
        if (authReqDTO.getDoSignAssertions()) {
            SAMLSSOUtil.setSignature(samlAssertion, authReqDTO.getSigningAlgorithmUri(), authReqDTO
                    .getDigestAlgorithmUri(), new SignKeyDataHolder(authReqDTO.getUser()
                    .getAuthenticatedSubjectIdentifier()));
        }
    }

    protected void setConditions(SAMLSSOAuthnReqDTO authReqDTO,  DateTime currentTime, DateTime notOnOrAfter,  Assertion samlAssertion) {
        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder()
                .buildObject();
        addAudience(audienceRestriction, authReqDTO.getIssuerWithDomain());
        // If an issuer qualifier is defined, it is removed from issuer value before including it in SAML Assertion.
        if (StringUtils.isNotEmpty(authReqDTO.getIssuerQualifier())) {
            addAudience(audienceRestriction, SAMLSSOUtil.getIssuerWithoutQualifier(authReqDTO.getIssuer()));
        }
        if (authReqDTO.getRequestedAudiences() != null) {
            for (String requestedAudience : authReqDTO.getRequestedAudiences()) {
                addAudience(audienceRestriction, requestedAudience);
            }
        }
        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(currentTime);
        conditions.setNotOnOrAfter(notOnOrAfter);
        conditions.getAudienceRestrictions().add(audienceRestriction);

        samlAssertion.setConditions(conditions);
    }

    private void addAudience(AudienceRestriction audienceRestriction, String requestedAudience) {

        Audience audience = new AudienceBuilder().buildObject();
        audience.setAudienceURI(requestedAudience);
        audienceRestriction.getAudiences().add(audience);
    }

    protected void addAttributeStatements(SAMLSSOAuthnReqDTO authReqDTO, Assertion samlAssertion) throws IdentityException{
        Map<String, String> claims = SAMLSSOUtil.getAttributes(authReqDTO);
        if (claims != null && !claims.isEmpty()) {
            AttributeStatement attrStmt = buildAttributeStatement(claims);
            if (attrStmt != null) {
                samlAssertion.getAttributeStatements().add(attrStmt);
            }
        }
    }

    /**
     * Add Authn Statement to the Assertion
     *
     * @param authReqDTO SAMLSSOAuthnReqDTO
     * @param sessionId Session Id
     * @param samlAssertion SAML Assertion
     */
    protected void addAuthStatement(SAMLSSOAuthnReqDTO authReqDTO, String sessionId, Assertion samlAssertion) {

        DateTime authnInstant;

        if (authReqDTO.getCreatedTimeStamp() != 0L) {
            authnInstant = new DateTime(authReqDTO.getCreatedTimeStamp());
        } else {
            authnInstant = new DateTime();
        }

        if (authReqDTO.getIdpAuthenticationContextProperties().get(SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF) != null
                && !authReqDTO.getIdpAuthenticationContextProperties().get(SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF)
                .isEmpty()) {

            List<AuthenticationContextProperty> authenticationContextProperties = authReqDTO
                    .getIdpAuthenticationContextProperties().get(SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF);

            for(AuthenticationContextProperty authenticationContextProperty : authenticationContextProperties) {
                if(authenticationContextProperty.getPassThroughData() != null) {
                    Map<String, Object> passThroughData = (Map<String, Object>) authenticationContextProperty
                            .getPassThroughData();
                    List<String> authnContextClassRefList;
                    if (passThroughData.get(SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF) != null) {
                        authnContextClassRefList = (List<String>) passThroughData.get(SAMLSSOConstants
                                .AUTHN_CONTEXT_CLASS_REF);
                        String idpEntityId = null;
                        if (passThroughData.get(IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID)
                                != null) {
                            idpEntityId = (String) passThroughData.get(IdentityApplicationConstants.Authenticator
                                    .SAML2SSO.IDP_ENTITY_ID);
                        }
                        DateTime applicableAuthnInstant = (DateTime) passThroughData.get(
                                SAMLSSOConstants.AUTHN_INSTANT);
                        if (applicableAuthnInstant == null) {
                            if(log.isDebugEnabled()) {
                                log.debug(
                                        "Treating AuthnInstant as current time, as it is not found in the pass-through data");
                            }
                            applicableAuthnInstant = authnInstant;
                        }
                        for (String authnContextClassRef : authnContextClassRefList) {
                            if (StringUtils.isNotBlank(authnContextClassRef)) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Passing AuthnContextClassRef: " + authnContextClassRef + " and " +
                                            "AuthenticatingAuthority:" + idpEntityId + " in the AuthnStatement");
                                }
                                samlAssertion.getAuthnStatements().add(getAuthnStatement(authReqDTO, sessionId,
                                        authnContextClassRef, applicableAuthnInstant, idpEntityId));
                            }
                        }
                    }
                }
            }
        }

        if (samlAssertion.getAuthnStatements().isEmpty()) {
            samlAssertion.getAuthnStatements().add(getAuthnStatement(authReqDTO, sessionId, AuthnContext
                    .PASSWORD_AUTHN_CTX, authnInstant, null));
        }
    }

    /**
     * Build AuthnStatement
     *
     * @param authReqDTO SAMLSSOAuthnReqDTO
     * @param sessionId session id
     * @param authnContextClassRef AuthnContextClassRef
     * @param authnInstant issue instance
     * @param idPEntityId idp entity id
     * @return AuthnStatement instance
     */
    private AuthnStatement getAuthnStatement(SAMLSSOAuthnReqDTO authReqDTO, String sessionId,
                                             String authnContextClassRef, DateTime authnInstant, String idPEntityId) {

        AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
        authStmt.setAuthnInstant(authnInstant);
        String sessionNotOnOrAfterValue = IdentityUtil.getProperty(IdentityConstants.ServerConfig.SAML_SESSION_NOT_ON_OR_AFTER_PERIOD);
        if (SAMLSSOUtil.isSAMLNotOnOrAfterPeriodDefined(sessionNotOnOrAfterValue)) {
            DateTime sessionNotOnOrAfter = new DateTime(authnInstant.getMillis() +
                    TimeUnit.SECONDS.toMillis((long) SAMLSSOUtil.getSAMLSessionNotOnOrAfterPeriod(sessionNotOnOrAfterValue)));
            authStmt.setSessionNotOnOrAfter(sessionNotOnOrAfter);
        }
        AuthnContext authContext = new AuthnContextBuilder().buildObject();
        AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
        authCtxClassRef.setAuthnContextClassRef(authnContextClassRef);
        authContext.setAuthnContextClassRef(authCtxClassRef);
        if(StringUtils.isNotBlank(idPEntityId)) {
            AuthenticatingAuthority authenticatingAuthority = new AuthenticatingAuthorityImpl();
            authenticatingAuthority.setURI(idPEntityId);
            authContext.getAuthenticatingAuthorities().add(authenticatingAuthority);
        }
        authStmt.setAuthnContext(authContext);
        if (authReqDTO.isDoSingleLogout()) {
            authStmt.setSessionIndex(sessionId);
        }
        return authStmt;
    }

    protected AttributeStatement buildAttributeStatement(Map<String, String> claims) {

        String claimSeparator = claims.get(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        if (StringUtils.isNotBlank(claimSeparator)) {
            userAttributeSeparator = claimSeparator;
        }
        claims.remove(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);

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
                attribute.setNameFormat(SAMLSSOConstants.NAME_FORMAT_BASIC);
                // look
                // https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUsrManJavaAnyTypes
                XSStringBuilder stringBuilder = (XSStringBuilder) XMLObjectProviderRegistrySupport.getBuilderFactory().
                        getBuilder(XSString.TYPE_NAME);
                XSString stringValue;

                //Need to check if the claim has multiple values
                if (userAttributeSeparator != null && claimValue.contains(userAttributeSeparator)) {
                    String[] claimValues = claimValue.split(Pattern.quote(userAttributeSeparator));
                    for (String attValue : claimValues) {
                        if (attValue != null && attValue.trim().length() > 0) {
                            stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                            stringValue.setValue(attValue);
                            attribute.getAttributeValues().add(stringValue);
                        }
                    }
                } else {
                    stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                    stringValue.setValue(claimValue);
                    attribute.getAttributeValues().add(stringValue);
                }

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
