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

import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.c14n.Canonicalizer;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.X509Data;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.w3c.dom.Element;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import javax.xml.namespace.QName;

public class SAMLTestRequestBuilder {
    private static Random random = new Random();

    public static AuthnRequest buildDefaultAuthnRequest() {
        return buildAuthnRequest(TestConstants.SP_ENTITY_ID, true, false, SAMLConstants.SAML2_POST_BINDING_URI,
                TestConstants.ACS_URL, TestConstants.SAML_SSO_IDP_URL);
    }

    public static AuthnRequest buildAuthnRequest(String SPEntityID, boolean isPassiveAuthn, boolean isForceAuthn,
                                                 String httpBinding, String ACSUrl, String destinationUrl) {

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject(SAMLSSOConstants.SAML_ASSERTION_URN,
                SAMLSSOConstants.FileBasedSPConfig.ISSUER, SAMLSSOConstants.FileBasedSPConfig.NAMESPACE_PREFIX);
        issuer.setValue(SPEntityID);

		/* NameIDPolicy */
        NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
        NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
        nameIdPolicy.setFormat(SAMLSSOConstants.NAMEID_FORMAT_PERSISTENT);
        nameIdPolicy.setSPNameQualifier(SAMLSSOConstants.FileBasedSPConfig.ISSUER);
        nameIdPolicy.setAllowCreate(true);

		/* AuthnContextClass */
        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef authnContextClassRef =
                authnContextClassRefBuilder.buildObject(SAMLSSOConstants.SAML_ASSERTION_URN,
                        SAMLSSOConstants.AUTHN_CONTEXT_CLASS_REF,
                        SAMLSSOConstants.FileBasedSPConfig.NAMESPACE_PREFIX);
        authnContextClassRef.setAuthnContextClassRef(SAMLSSOConstants.PASSWORD_PROTECTED_TRANSPORT_CLASS);

		/* AuthnContex */
        RequestedAuthnContextBuilder requestedAuthnContextBuilder =
                new RequestedAuthnContextBuilder();
        RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        DateTime issueInstant = new DateTime();

		/* AuthRequestObject */
        AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authRequest =
                authRequestBuilder.buildObject(SAMLSSOConstants.SAML_PROTOCOL_URN,
                        SAMLSSOConstants.AUTHN_REQUEST, SAMLSSOConstants.FileBasedSPConfig.NAMESPACE_PREFIX);

        authRequest.setForceAuthn(isForceAuthn);
        authRequest.setIsPassive(isPassiveAuthn);
        authRequest.setIssueInstant(issueInstant);
        authRequest.setProtocolBinding(httpBinding);
        authRequest.setAssertionConsumerServiceURL(ACSUrl);
        authRequest.setIssuer(issuer);
        authRequest.setNameIDPolicy(nameIdPolicy);
        authRequest.setRequestedAuthnContext(requestedAuthnContext);
        authRequest.setID(createID());
        authRequest.setVersion(SAMLVersion.VERSION_20);
        authRequest.setDestination(destinationUrl);

        return authRequest;
    }

    public static AuthnRequest buildAuthnRequest(String SPEntityID, boolean isPassiveAuthn, boolean isForceAuthn,
                                                 String httpBinding, String ACSUrl, String destinationUrl,
                                                 Extensions extensions) {
        AuthnRequest authRequest = buildAuthnRequest(SPEntityID, isPassiveAuthn, isForceAuthn, httpBinding, ACSUrl,
                destinationUrl);
        authRequest.setExtensions(extensions);
        return authRequest;
    }

    public static AuthnRequest buildAuthnRequest(String SPEntityID, boolean isPassiveAuthn, boolean isForceAuthn,
                                                 String httpBinding, String ACSUrl, String destinationUrl,
                                                 Integer consumerServiceIndex) {
        AuthnRequest authRequest = buildAuthnRequest(SPEntityID, isPassiveAuthn, isForceAuthn, httpBinding, ACSUrl,
                destinationUrl);
        // Requesting Attributes. This Index value is registered in the IDP.
        authRequest.setAssertionConsumerServiceIndex(consumerServiceIndex);
        return authRequest;
    }

    public static AuthnRequest buildAuthnRequest(String SPEntityID, boolean isPassiveAuthn, boolean isForceAuthn,
                                                 String httpBinding, String ACSUrl, String destinationUrl,
                                                 Extensions extensions, Integer consumerServiceIndex) {
        AuthnRequest authRequest = buildAuthnRequest(SPEntityID, isPassiveAuthn, isForceAuthn, httpBinding, ACSUrl,
                destinationUrl);
        authRequest.setExtensions(extensions);
        // Requesting Attributes. This Index value is registered in the IDP.
        authRequest.setAssertionConsumerServiceIndex(consumerServiceIndex);
        return authRequest;
    }

    /**
     * Generates a unique Id for Authentication Requests.
     *
     * @return Generated unique Id
     */
    private static String createID() {

        byte[] bytes = new byte[20]; // 160 bit

        random.nextBytes(bytes);

        char[] charMapping = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};

        char[] chars = new char[40];

        for (int i = 0; i < bytes.length; i++) {
            int left = (bytes[i] >> 4) & 0x0f;
            int right = bytes[i] & 0x0f;
            chars[i * 2] = charMapping[left];
            chars[i * 2 + 1] = charMapping[right];
        }

        return String.valueOf(chars);
    }

    public static String encodeRequestMessage(RequestAbstractType requestMessage) throws MarshallingException,
            IOException, InitializationException {
        SAMLInitializer.doBootstrap();
        System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(requestMessage);
        Element authDOM = null;
        authDOM = marshaller.marshall(requestMessage);

        /* Compress the message */
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
        SerializeSupport.writeNode(authDOM, deflaterOutputStream);
        deflaterOutputStream.close();

        /* Encoding the compressed message */
        String encodedRequestMessage = Base64Support.encode(byteArrayOutputStream.toByteArray(), Base64Support.UNCHUNKED);

        byteArrayOutputStream.write(byteArrayOutputStream.toByteArray());
        byteArrayOutputStream.toString();

        return encodedRequestMessage;
    }

    public static void addSignatureToHTTPQueryString(StringBuilder httpQueryString,
                                                     String signatureAlgorithmURI, X509Credential credential) throws
            UnsupportedEncodingException, org.opensaml.security.SecurityException {
        httpQueryString.append("&SigAlg=");
        httpQueryString.append(URLEncoder.encode(signatureAlgorithmURI, "UTF-8").trim());
        byte[] rawSignature = XMLSigningUtil.signWithURI(credential, signatureAlgorithmURI,
                httpQueryString.toString().getBytes("UTF-8"));

        String base64Signature = Base64Support.encode(rawSignature, Base64Support.UNCHUNKED);
        httpQueryString.append("&Signature=" + URLEncoder.encode(base64Signature, "UTF-8").trim());
    }

    /**
     * Add Signature to xml post request
     *
     * @param request            AuthnReuqest
     * @param signatureAlgorithm Signature Algorithm
     * @param digestAlgorithm    Digest algorithm to be used while digesting message
     * @param includeCert        Whether to include certificate in request or not
     * @param x509Credential     Credentials
     * @throws Exception
     */
    public static void setSignature(RequestAbstractType request, String signatureAlgorithm,
                                    String digestAlgorithm, boolean includeCert, X509Credential x509Credential)
            throws Exception {
        SAMLInitializer.doBootstrap();
        if (StringUtils.isEmpty(signatureAlgorithm)) {
            signatureAlgorithm = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms().get(
                    IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1);
        }
        if (StringUtils.isEmpty(digestAlgorithm)) {
            digestAlgorithm = IdentityApplicationManagementUtil.getXMLDigestAlgorithms().get(
                    IdentityApplicationConstants.XML.DigestAlgorithm.SHA1);
        }

        Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(x509Credential);
        signature.setSignatureAlgorithm(signatureAlgorithm);
        signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        if (includeCert) {
            KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
            org.opensaml.xmlsec.signature.X509Certificate cert = (org.opensaml.xmlsec.signature.X509Certificate)
                    buildXMLObject(org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
            String value = null;
            value = org.apache.xml.security.utils.Base64.encode(x509Credential.getEntityCertificate().getEncoded());
            cert.setValue(value);
            data.getX509Certificates().add(cert);
            keyInfo.getX509Datas().add(data);
            signature.setKeyInfo(keyInfo);
        }

        request.setSignature(signature);
        ((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(digestAlgorithm);

        List<Signature> signatureList = new ArrayList<Signature>();
        signatureList.add(signature);
        // Marshall and Sign
        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(request);
        marshaller.marshall(request);
        org.apache.xml.security.Init.init();
        Signer.signObjects(signatureList);
    }

    /**
     * Base64 encode XML string
     *
     * @param xmlString Unmarshelled xml string
     * @return Base 64 encoded xml string
     */
    public static String encode(String xmlString) {
        String encodedRequestMessage = Base64Support.encode(xmlString.getBytes(), Base64Support.UNCHUNKED);
        return encodedRequestMessage.trim();
    }

    private static XMLObject buildXMLObject(QName objectQName) {
        XMLObjectBuilder builder = XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(objectQName);
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
    }

}
