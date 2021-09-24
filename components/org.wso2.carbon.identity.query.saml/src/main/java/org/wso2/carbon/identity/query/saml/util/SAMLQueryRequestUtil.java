/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.query.saml.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xerces.impl.Constants;
import org.apache.xerces.util.SecurityManager;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.AuthzDecisionStatement;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.persistence.IdentityPersistenceManager;
import org.wso2.carbon.identity.query.saml.SignKeyDataHolder;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Map;


public class SAMLQueryRequestUtil {

    private static final Log log = LogFactory.getLog(SAMLQueryRequestUtil.class);
    private static final int ENTITY_EXPANSION_LIMIT = 0;
    private static boolean isBootstrapped = false;

    /**
     * convert xml string into DOM object
     *
     * @param xmlString XML content in string format
     * @return XMLObject well-formed XML object
     * @throws IdentitySAML2QueryException if unable to unmarshall request message
     */
    public static XMLObject unmarshall(String xmlString) throws IdentitySAML2QueryException {
        InputStream inputStream;
        try {
            doBootstrap();
            DocumentBuilderFactory documentBuilderFactory = getSecuredDocumentBuilderFactory();
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            inputStream = new ByteArrayInputStream(xmlString.trim().getBytes(StandardCharsets.UTF_8));
            Document document = docBuilder.parse(inputStream);
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (IOException e) {
            log.error("Unable to parse inputstream", e);
            throw new IdentitySAML2QueryException("Unable to parse inputstream");
        } catch (UnmarshallingException e) {
            log.error("Unable unmarshall XML element", e);
            throw new IdentitySAML2QueryException("Unable unmarshall XML element");
        } catch (ParserConfigurationException e) {
            log.error("Unable to initiate document builder", e);
            throw new IdentitySAML2QueryException("Unable to initiate document builder");
        } catch (SAXException e) {
            log.error("Unable to parse inputstream", e);
            throw new IdentitySAML2QueryException("Unable to parse inputstream");
        } catch (IdentityException e) {
            log.error("Unable to bootstrap while unmarshall", e);
            throw new IdentitySAML2QueryException("Unable to bootstrap while unmarshall");
        }

    }

    /**
     * Create DocumentBuilderFactory with the XXE and XEE prevention measurements.
     *
     * @return DocumentBuilderFactory instance
     */
    public static DocumentBuilderFactory getSecuredDocumentBuilderFactory() throws  IdentitySAML2QueryException{

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        try {
            dbf.setFeature(Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE, false);
            dbf.setFeature(Constants.SAX_FEATURE_PREFIX + Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE, false);
            dbf.setFeature(Constants.XERCES_FEATURE_PREFIX + Constants.LOAD_EXTERNAL_DTD_FEATURE, false);
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setNamespaceAware(true);
            dbf.setExpandEntityReferences(false);
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        } catch (ParserConfigurationException e) {
            log.error("Failed to load XML Processor Feature " + Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE + " or " +
                    Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE + " or " + Constants.LOAD_EXTERNAL_DTD_FEATURE +
                    " or secure-processing.");
            throw new IdentitySAML2QueryException("Failed to load XML Processor Feature " + Constants.EXTERNAL_GENERAL_ENTITIES_FEATURE + " or " +
                    Constants.EXTERNAL_PARAMETER_ENTITIES_FEATURE + " or " + Constants.LOAD_EXTERNAL_DTD_FEATURE +
                    " or secure-processing.",e);
        }

        SecurityManager securityManager = new SecurityManager();
        securityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT);
        dbf.setAttribute(Constants.XERCES_PROPERTY_PREFIX + Constants.SECURITY_MANAGER_PROPERTY, securityManager);

        return dbf;

    }


    /**
     * Initializes the OpenSAML library modules, if not initialized yet.
     *
     * @throws IdentitySAML2QueryException If unable to initialize
     */
    public static void doBootstrap() throws IdentitySAML2QueryException {
        try {
            if (!isBootstrapped) {
                SAMLInitializer.doBootstrap();
                isBootstrapped = true;
            }
        } catch (InitializationException e) {
            log.error("Unable to initialize OpenSAML library", e);
            throw new IdentitySAML2QueryException("Unable to initialize OpenSAML library");
        }

    }

    /**
     * This method is used to load Service Provider Configurations
     *
     * @param issuer issuer name
     * @return SAMLSSOServiceProviderDO issuer config instance
     * @throws IdentitySAML2QueryException If unable to get issuer information
     */
    public static SAMLSSOServiceProviderDO getServiceProviderConfig(String issuer)
            throws IdentitySAML2QueryException {
        try {
            SSOServiceProviderConfigManager idPConfigManager =
                    SSOServiceProviderConfigManager.getInstance();
            SAMLSSOServiceProviderDO ssoIdpConfigs = idPConfigManager.getServiceProvider(issuer);
            if (ssoIdpConfigs == null) {
                IdentityPersistenceManager persistenceManager =
                        IdentityPersistenceManager.getPersistanceManager();
                int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
                UserRegistry registry =
                        SAMLSSOUtil.getRegistryService()
                                .getConfigSystemRegistry(tenantId);
                ssoIdpConfigs = persistenceManager.getServiceProvider(registry, issuer);
            }
            return ssoIdpConfigs;
        } catch (RegistryException e) {
            log.error("Unable to load registry service", e);
            throw new IdentitySAML2QueryException("Unable to load registry service");

        } catch (IdentityException e) {
            log.error("Unable to load Identity persistence service manager", e);
            throw new IdentitySAML2QueryException("Unable to load Identity persistence service manager");
        }
    }

    /**
     * this method is used to build SAML2.0 assertion
     *
     * @param ssoIdPConfigs          issuer information
     * @param tenantDomain           tenant domain of issuer
     * @param authzDecisionStatement authentication decision statements
     * @return Assertion set of elements contain inside assertion
     * @throws IdentitySAML2QueryException If unable to collect issuer information
     */
    public static Assertion buildSAMLAssertion(String tenantDomain, AuthzDecisionStatement authzDecisionStatement,
                                               SAMLSSOServiceProviderDO ssoIdPConfigs)
            throws IdentitySAML2QueryException {

        DateTime currentTime = new DateTime();
        DateTime notOnOrAfter =
                new DateTime(currentTime.getMillis() +
                        (long) SAMLSSOUtil.getSAMLResponseValidityPeriod() * 60 *
                                1000);
        Assertion samlAssertion = new AssertionBuilder().buildObject();
        samlAssertion.setID(SAMLSSOUtil.createID());
        samlAssertion.setVersion(SAMLVersion.VERSION_20);
        samlAssertion.setIssuer(OpenSAML3Util.getIssuer("carbon.super"));
        samlAssertion.setIssueInstant(currentTime);
        Subject subject = new SubjectBuilder().buildObject();
        NameID nameId = new NameIDBuilder().buildObject();

        if (ssoIdPConfigs.getNameIDFormat() != null) {
            nameId.setFormat(ssoIdPConfigs.getNameIDFormat());
        } else {
            nameId.setFormat(NameIdentifier.UNSPECIFIED);
        }
        subject.setNameID(nameId);

        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);

        SubjectConfirmationData subjectConfirmationData =
                new SubjectConfirmationDataBuilder().buildObject();
        subjectConfirmationData.setRecipient(ssoIdPConfigs.getAssertionConsumerUrl());
        subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        samlAssertion.setSubject(subject);

        AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
        authStmt.setAuthnInstant(new DateTime());

        AuthnContext authContext = new AuthnContextBuilder().buildObject();
        AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
        authCtxClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authContext.setAuthnContextClassRef(authCtxClassRef);
        authStmt.setAuthnContext(authContext);
        samlAssertion.getAuthnStatements().add(authStmt);

        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
        Audience issuerAudience = new AudienceBuilder().buildObject();
        issuerAudience.setAudienceURI(ssoIdPConfigs.getIssuer());
        audienceRestriction.getAudiences().add(issuerAudience);
        if (ssoIdPConfigs.getRequestedAudiences() != null) {
            for (String requestedAudience : ssoIdPConfigs.getRequestedAudiences()) {
                Audience audience = new AudienceBuilder().buildObject();
                audience.setAudienceURI(requestedAudience);
                audienceRestriction.getAudiences().add(audience);
            }
        }

        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(currentTime);
        conditions.setNotOnOrAfter(notOnOrAfter);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        samlAssertion.setConditions(conditions);

        samlAssertion.getAuthzDecisionStatements().add(authzDecisionStatement);

        if (ssoIdPConfigs.isDoSignAssertions()) {

            try {
                OpenSAML3Util.setSignature(samlAssertion, ssoIdPConfigs.getSigningAlgorithmUri(), ssoIdPConfigs
                        .getDigestAlgorithmUri(), new SignKeyDataHolder(tenantDomain));
            } catch (IdentityException e) {
                log.error("Unable to set signature to the Assertion", e);
                throw new IdentitySAML2QueryException("Unable to set signature to the Assertion");
            }
        }

        return samlAssertion;
    }

    /**
     * this method is used to build SAML2.0 assertion
     *
     * @param ssoIdPConfigs issuer information
     * @param tenantDomain  tenant domain of issuer
     * @param claims        List of requested claims
     * @return Assertion set of elements contain inside assertion
     * @throws IdentitySAML2QueryException If unable to collect issuer information
     */
    public static Assertion buildSAMLAssertion(String tenantDomain, Map<String, String> claims,
                                               SAMLSSOServiceProviderDO ssoIdPConfigs)
            throws IdentitySAML2QueryException {

        DateTime currentTime = new DateTime();
        DateTime notOnOrAfter =
                new DateTime(currentTime.getMillis() +
                        (long) SAMLSSOUtil.getSAMLResponseValidityPeriod() * 60 *
                                1000);
        Assertion samlAssertion = new AssertionBuilder().buildObject();
        samlAssertion.setID(SAMLSSOUtil.createID());
        samlAssertion.setVersion(SAMLVersion.VERSION_20);
        samlAssertion.setIssuer(OpenSAML3Util.getIssuer("carbon.super"));
        samlAssertion.setIssueInstant(currentTime);
        Subject subject = new SubjectBuilder().buildObject();
        NameID nameId = new NameIDBuilder().buildObject();


        if (ssoIdPConfigs.getNameIDFormat() != null) {
            nameId.setFormat(ssoIdPConfigs.getNameIDFormat());
        } else {
            nameId.setFormat(NameIdentifier.UNSPECIFIED);
        }

        subject.setNameID(nameId);

        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);

        SubjectConfirmationData subjectConfirmationData =
                new SubjectConfirmationDataBuilder().buildObject();
        subjectConfirmationData.setRecipient(ssoIdPConfigs.getAssertionConsumerUrl());
        subjectConfirmationData.setNotOnOrAfter(notOnOrAfter);

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        samlAssertion.setSubject(subject);

        AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
        authStmt.setAuthnInstant(new DateTime());

        AuthnContext authContext = new AuthnContextBuilder().buildObject();
        AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
        authCtxClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authContext.setAuthnContextClassRef(authCtxClassRef);
        authStmt.setAuthnContext(authContext);
        samlAssertion.getAuthnStatements().add(authStmt);

        if (claims != null) {
            samlAssertion.getAttributeStatements().add(buildAttributeStatement(claims));
        }

        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
        Audience issuerAudience = new AudienceBuilder().buildObject();
        issuerAudience.setAudienceURI(ssoIdPConfigs.getIssuer());
        audienceRestriction.getAudiences().add(issuerAudience);
        if (ssoIdPConfigs.getRequestedAudiences() != null) {
            for (String requestedAudience : ssoIdPConfigs.getRequestedAudiences()) {
                Audience audience = new AudienceBuilder().buildObject();
                audience.setAudienceURI(requestedAudience);
                audienceRestriction.getAudiences().add(audience);
            }
        }

        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.setNotBefore(currentTime);
        conditions.setNotOnOrAfter(notOnOrAfter);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        samlAssertion.setConditions(conditions);

        if (ssoIdPConfigs.isDoSignAssertions()) {

            try {
                OpenSAML3Util.setSignature(samlAssertion, ssoIdPConfigs.getSigningAlgorithmUri(), ssoIdPConfigs
                        .getDigestAlgorithmUri(), new SignKeyDataHolder(tenantDomain));
            } catch (IdentityException e) {
                log.error("Unable to set signature to the Assertion", e);
                throw new IdentitySAML2QueryException("Unable to set signature to the Assertion");
            }
        }

        return samlAssertion;
    }


    /**
     * This method is used to build Attribute Statement including user attributes
     *
     * @param claims List of requested claims
     * @return AttributeStatement set of attributes contain inside attribute statement
     * @throws  IdentitySAML2QueryException If unable to filter attributes from Map
     */

    public static AttributeStatement buildAttributeStatement(Map<String, String> claims) throws IdentitySAML2QueryException {
        AttributeStatement attStmt = null;
        if (claims != null) {
            attStmt = new AttributeStatementBuilder().buildObject();
            Iterator<String> iterator = claims.keySet().iterator();

            for (int i = 0; i < claims.size(); i++) {
                Attribute attrib = new AttributeBuilder().buildObject();
                String claimUri = iterator.next();
                attrib.setName(claimUri);
                XSStringBuilder stringBuilder =
                        (XSStringBuilder) XMLObjectProviderRegistrySupport.getBuilderFactory()
                                .getBuilder(XSString.TYPE_NAME);
                XSString stringValue =
                        stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                                XSString.TYPE_NAME);
                stringValue.setValue(claims.get(claimUri));
                attrib.getAttributeValues().add(stringValue);
                attStmt.getAttributes().add(attrib);
            }
        }
        return attStmt;
    }

    /**
     * This method is used to serialize response message
     *
     * @param xmlObject well formed XML object
     * @return String serialized response
     * @throws IdentitySAML2QueryException If unable to marshall response
     */
    public static String marshall(XMLObject xmlObject) throws IdentitySAML2QueryException {

        ByteArrayOutputStream byteArrayOutputStrm = null;
        try {
            doBootstrap();
            System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                    "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");
            MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);
            byteArrayOutputStrm = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(byteArrayOutputStrm);
            writer.write(element, output);
            return byteArrayOutputStrm.toString(SAMLQueryRequestConstants.GenericConstants.UTF8_ENC);
        } catch (IdentityException e) {
            log.error("Error de-serializing the SAML Response", e);
            throw new IdentitySAML2QueryException("Error de-serializing the SAML Response");
        } catch (UnsupportedEncodingException e) {
            log.error("XML message contain invalid Encoding", e);
            throw new IdentitySAML2QueryException("XML message contain invalid Encoding");
        } catch (MarshallingException e) {
            log.error("Unable to marshall", e);
            throw new IdentitySAML2QueryException("Unable to marshall");
        } catch (IllegalAccessException e) {
            log.error("Illegal Access", e);
            throw new IdentitySAML2QueryException("Illegal Access");
        } catch (InstantiationException e) {
            log.error("Unable to initialize", e);
            throw new IdentitySAML2QueryException("Unable to initialize");
        } catch (ClassNotFoundException e) {
            log.error("Class not found", e);
            throw new IdentitySAML2QueryException("Class not found");
        } catch (NullPointerException e) {
            log.error("Marshall throw null pointer exception", e);
            throw new IdentitySAML2QueryException("Marshall throw null pointer exception");
        } finally {
            if (byteArrayOutputStrm != null) {
                try {
                    byteArrayOutputStrm.close();
                } catch (IOException e) {
                    log.error("Error while closing the stream", e);
                }
            }
        }
    }

}
