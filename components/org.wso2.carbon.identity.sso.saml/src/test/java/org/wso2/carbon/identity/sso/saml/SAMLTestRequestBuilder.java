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

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SigningUtil;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Random;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public class SAMLTestRequestBuilder {
    private static Random random = new Random();

    public static AuthnRequest buildDefaultAuthnRequest(){
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
            IOException, ConfigurationException {
        DefaultBootstrap.bootstrap();
        System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(requestMessage);
        Element authDOM = null;
        authDOM = marshaller.marshall(requestMessage);

        /* Compress the message */
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
        StringWriter rspWrt = new StringWriter();
        XMLHelper.writeNode(authDOM, rspWrt);
        deflaterOutputStream.write(rspWrt.toString().getBytes());
        deflaterOutputStream.close();

        /* Encoding the compressed message */
        String encodedRequestMessage = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);

        byteArrayOutputStream.write(byteArrayOutputStream.toByteArray());
        byteArrayOutputStream.toString();

        return encodedRequestMessage;
    }

    public static void addSignatureToHTTPQueryString(StringBuilder httpQueryString,
                                                     String signatureAlgorithmURI, X509Credential credential) throws
            UnsupportedEncodingException, org.opensaml.xml.security.SecurityException {
        httpQueryString.append("&SigAlg=");
        httpQueryString.append(URLEncoder.encode(signatureAlgorithmURI, "UTF-8").trim());
        byte[] rawSignature = SigningUtil.signWithURI(credential, signatureAlgorithmURI,
                httpQueryString.toString().getBytes("UTF-8"));

        String base64Signature = Base64.encodeBytes(rawSignature, Base64.DONT_BREAK_LINES);
        httpQueryString.append("&Signature=" + URLEncoder.encode(base64Signature, "UTF-8").trim());
    }

}
