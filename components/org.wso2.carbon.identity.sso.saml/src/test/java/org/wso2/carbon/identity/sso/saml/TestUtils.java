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
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import javax.servlet.http.HttpServletRequest;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Random;

public class TestUtils {

    private static Random random = new Random();

    public static KeyStore loadKeyStoreFromFileSystem(String keyStorePath, String password, String type) {
        try (FileInputStream inputStream = new FileInputStream(keyStorePath)) {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(inputStream, password.toCharArray());
            return keyStore;
        } catch (Exception e) {
            String errorMsg = "Error loading the key store from the given location.";
            throw new SecurityException(errorMsg, e);
        }
    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "conf", fileName).toString();
        }
        return null;
    }

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
}
