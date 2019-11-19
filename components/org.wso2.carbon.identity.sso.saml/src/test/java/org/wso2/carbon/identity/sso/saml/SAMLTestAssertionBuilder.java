/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.sso.saml;

import java.util.HashMap;
import java.util.Map;
import org.joda.time.DateTime;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

public class SAMLTestAssertionBuilder {

    public static Assertion buildDefaultSAMLAssertion(){
        Map<String, String> userAttributes = new HashMap<>();
        userAttributes.put("first_name", "John");
        userAttributes.put("last_name", "Snow");
        userAttributes.put("email", "johnsnow@got.com");
        return buildSAMLAssertion("is.com", "userJohnSnow", "abcdef1234567", "google.com", userAttributes);
    }

    public static Assertion buildSAMLAssertion(String issuerStr, String nameIdStr, String sessionId,
                                               String idpEntityId, Map<String, String> userAttributeMap) {
        DateTime now = new DateTime();
        DateTime notOnOrAfter = now.plusMinutes(15);

        Assertion samlAssertion = new AssertionBuilder().buildObject();

        // Create issuer.
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(issuerStr);
        issuer.setFormat(NameIDType.ENTITY);

        // Create nameID.
        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setValue(nameIdStr);
        nameId.setFormat(NameIDType.EMAIL);

        // Create subjectConfirmation.
        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);
        SubjectConfirmationData scData = new SubjectConfirmationDataBuilder().buildObject();
        scData.setRecipient(TestConstants.ACS_URL);
        scData.setNotOnOrAfter(notOnOrAfter);
        subjectConfirmation.setSubjectConfirmationData(scData);

        // Create subject.
        Subject subject = new SubjectBuilder().buildObject();
        subject.setNameID(nameId);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        // Create authentication statement.
        // Creating authentication context class reference.
        AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
        authCtxClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        // Creating authenticating authority.
        AuthenticatingAuthority authenticatingAuthority = new org.wso2.carbon.identity.sso.saml.builders.AuthenticatingAuthorityImpl();
        authenticatingAuthority.setURI(idpEntityId);
        // Creating authentication context
        AuthnContext authContext = new AuthnContextBuilder().buildObject();
        authContext.setAuthnContextClassRef(authCtxClassRef);
        authContext.getAuthenticatingAuthorities().add(authenticatingAuthority);
        // Creating authnStatement.
        AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
        authStmt.setAuthnInstant(now);
        authStmt.setSessionIndex(sessionId);
        authStmt.setAuthnContext(authContext);

        // Create attributeStatement.
        AttributeStatement attStmt = new AttributeStatementBuilder().buildObject();
        XSStringBuilder stringBuilder = new XSStringBuilder();
        for(Map.Entry<String, String> entry : userAttributeMap.entrySet()){
            Attribute attribute = new AttributeBuilder().buildObject();
            // Setting attribute name.
            attribute.setName(entry.getKey());
            // Setting attribute name format.
            attribute.setNameFormat(SAMLSSOConstants.NAME_FORMAT_BASIC);
            // Creating attribute value.
            XSString stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
            stringValue.setValue(entry.getValue());
            // Setting attribute value to attribute values list.
            attribute.getAttributeValues().add(stringValue);
            // Setting attribute to attributeStatement.
            attStmt.getAttributes().add(attribute);
        }

        // Create conditions.
        // Creating audience restriction.
        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
        Audience issuerAudience = new AudienceBuilder().buildObject();
        issuerAudience.setAudienceURI(TestConstants.IDP_URL);
        audienceRestriction.getAudiences().add(issuerAudience);
        // Creating conditions.
        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(now);
        conditions.setNotOnOrAfter(notOnOrAfter);
        conditions.getAudienceRestrictions().add(audienceRestriction);

        // Set basic information.
        samlAssertion.setID(SAMLSSOUtil.createID());
        samlAssertion.setVersion(SAMLVersion.VERSION_20);
        samlAssertion.setIssuer(issuer);
        samlAssertion.setIssueInstant(now);

        // Set subject.
        samlAssertion.setSubject(subject);

        // Set authentication statement.
        samlAssertion.getAuthnStatements().add(authStmt);

        // Set attribute statement.
        samlAssertion.getAttributeStatements().add(attStmt);

        // Set conditions.
        samlAssertion.setConditions(conditions);

        return samlAssertion;
    }
}

