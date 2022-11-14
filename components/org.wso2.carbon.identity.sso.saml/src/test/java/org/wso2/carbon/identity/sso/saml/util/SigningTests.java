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

package org.wso2.carbon.identity.sso.saml.util;

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mockito.Mock;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.security.x509.X509Credential;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLTestRequestBuilder;
import org.wso2.carbon.identity.sso.saml.TestConstants;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;


/**
 * Tests request signing functionality.
 */
@PrepareForTest({IdentityUtil.class, IdentityProviderManager.class})
@PowerMockIgnore({"javax.net.*", "javax.security.*", "javax.xml.*", "org.xml.*",
        "org.w3c.dom.*", "org.apache.xerces.*", "org.mockito.*"})
public class SigningTests extends PowerMockTestCase {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @Mock
    private RealmService realmService;

    @Mock
    private TenantManager tenantManager;

    @Mock
    private IdentityProviderManager identityProviderManager;

    @Mock
    private IdentityProvider identityProvider;

    @Mock
    private FederatedAuthenticatorConfig federatedAuthenticatorConfig;

    @Mock
    private X509Credential x509Credential;

    private final String signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    private final String SAML2_REDIRECT_SIGNATURE_VALIDATOR =
            "org.wso2.carbon.identity.sso.saml.validators.SAML2HTTPRedirectDeflateSignatureValidator";
    private final String SAML2_DEFAULT_SIGNER =
            "org.wso2.carbon.identity.sso.saml.builders.signature.DefaultSSOSigner";
    private final String REDIRECT_SIGNATURE_VALIDATOR_PROPERTY = "SSOService.SAML2HTTPRedirectSignatureValidator";

    @BeforeTest
    public void setUp() throws Exception {

        TestUtils.startTenantFlow(org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @DataProvider
    public Object[][] getSignatureParams() {
        return new Object[][]{
                {true, null, null, signatureAlgorithm, true, "Signature is set properly. Hence signature should" +
                        " be validated"},
                {false, null, null, signatureAlgorithm, false, "Signature is not set in the request. Hence " +
                        "signature should not be validated"},
                {false, "WrongMessage", null, signatureAlgorithm, false, "Invalid request is given. Hence " +
                        "should not be able to validate"},
                {false, null, null, signatureAlgorithm + "dummy", false, "Invalid Algorithm is provided. Hence " +
                        "validation should fail"},
                {true, null, null, signatureAlgorithm, true, "Query string is not appended. Hence should fail"},
        };
    }

    @Test(dataProvider = "getSignatureParams")
    public void testSignatureValidate(boolean addSignature, String prependEncodedMessage, String signature, String
            algorithm, boolean expected, String message) throws Exception {

        // This is done to avoid info logs which represent "Algorithm not registered"
        Security.addProvider(new BouncyCastleProvider());

        prepareForGetIssuer();
        TestUtils.prepareCredentials(x509Credential);
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(REDIRECT_SIGNATURE_VALIDATOR_PROPERTY)).thenReturn
                (SAML2_REDIRECT_SIGNATURE_VALIDATOR);
        when(IdentityUtil.getSecuredDocumentBuilderFactory()).thenCallRealMethod();

        AuthnRequest authnReq = SAMLTestRequestBuilder.buildAuthnRequest(TestConstants.TRAVELOCITY_ISSUER, false, false,
                HTTPConstants.HTTP_METHOD_GET, TestConstants.TRAVELOCITY_ISSUER, TestConstants.IDP_URL);
        String encodedMessage = SAMLTestRequestBuilder.encodeRequestMessage(authnReq);
        if (StringUtils.isNotEmpty(prependEncodedMessage)) {
            encodedMessage = prependEncodedMessage + encodedMessage;
        }
        Map<String, String> inputAttributes = new HashMap<>();
        inputAttributes.put(TestConstants.CLAIM_URI1, TestConstants.CLAIM_VALUE1);
        inputAttributes.put(TestConstants.CLAIM_URI2, TestConstants.CLAIM_VALUE2);
        SAMLSSOAuthnReqDTO samlssoAuthnReqDTO = TestUtils.buildAuthnReqDTO(inputAttributes,
                TestConstants.SAMPLE_NAME_ID_FORMAT, TestConstants.LOACALHOST_DOMAIN, TestConstants.TEST_USER_NAME);
        samlssoAuthnReqDTO.setQueryString("SAMLRequest=" + encodedMessage);
        samlssoAuthnReqDTO.setRequestMessageString(encodedMessage);
        samlssoAuthnReqDTO.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        samlssoAuthnReqDTO.setCertAlias(TestConstants.WSO2_CARBON);
        samlssoAuthnReqDTO.setStratosDeployment(true);
        StringBuilder stringBuilder = new StringBuilder(samlssoAuthnReqDTO.getQueryString());
        if (addSignature && StringUtils.isBlank(signature)) {
            SAMLTestRequestBuilder.addSignatureToHTTPQueryString(stringBuilder,
                    algorithm, x509Credential);
        }
        if (StringUtils.isNotBlank(signature)) {
            stringBuilder.append("&Signature=" + signature).append("&SigAlg=" + algorithm);
        }
        samlssoAuthnReqDTO.setQueryString(stringBuilder.toString());
        assertEquals(SAMLSSOUtil.validateAuthnRequestSignature(samlssoAuthnReqDTO,
                x509Credential.getEntityCertificate()), expected, message);
    }

    @DataProvider
    public Object[][] getPostSignatureParams() {
        return new Object[][]{
                {true, false, false, SAML2_DEFAULT_SIGNER, true, "Valid signature is added. Hence signature should " +
                        "validate"},
                {true, true, false, SAML2_DEFAULT_SIGNER, false, "Content of the signature is changed. Hence should " +
                        "fail"},
                {true, true, false, SAML2_DEFAULT_SIGNER + "NonExisting", false, "Non existing validator class is " +
                        "given. Hence validation should fail"},
        };
    }

    @Test(dataProvider = "getPostSignatureParams")
    public void validateXMLSignatureTest(boolean addSignature, boolean manipulateXML, boolean changeSignature, String
            ssoSigner, boolean expected, String message) throws Exception {

        prepareForGetIssuer();
        TestUtils.prepareCredentials(x509Credential);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty("SSOService.SAMLSSOSigner")).thenReturn(ssoSigner);
        when(IdentityUtil.getSecuredDocumentBuilderFactory()).thenCallRealMethod();

        AuthnRequest authnReq = SAMLTestRequestBuilder.buildAuthnRequest(TestConstants.TRAVELOCITY_ISSUER, false, false,
                HTTPConstants.HTTP_METHOD_POST, TestConstants.TRAVELOCITY_ISSUER, TestConstants.IDP_URL);
        if (addSignature) {
            SAMLTestRequestBuilder.setSignature(authnReq, null, null, true, x509Credential);
        }
        if (manipulateXML) {
            authnReq.getIssuer().setValue("ManipulatedIssuer");
        }
        String encodedMessage = SAMLTestRequestBuilder.encode(SAMLSSOUtil.marshall(authnReq));
        Map<String, String> inputAttributes = new HashMap<>();
        inputAttributes.put(TestConstants.CLAIM_URI1, TestConstants.CLAIM_VALUE1);
        inputAttributes.put(TestConstants.CLAIM_URI2, TestConstants.CLAIM_VALUE2);
        SAMLSSOAuthnReqDTO samlssoAuthnReqDTO = TestUtils.buildAuthnReqDTO(inputAttributes,
                TestConstants.SAMPLE_NAME_ID_FORMAT, TestConstants.LOACALHOST_DOMAIN, TestConstants.TEST_USER_NAME);
        samlssoAuthnReqDTO.setRequestMessageString(encodedMessage);
        samlssoAuthnReqDTO.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        samlssoAuthnReqDTO.setCertAlias(TestConstants.WSO2_CARBON);
        samlssoAuthnReqDTO.setStratosDeployment(true);

        assertEquals(SAMLSSOUtil.validateAuthnRequestSignature(samlssoAuthnReqDTO,
                x509Credential.getEntityCertificate()), expected, message);
    }

    private void prepareForGetIssuer() throws Exception {

        when(tenantManager.getTenantId(anyString())).thenReturn(-1234);
        when(realmService.getTenantManager()).thenReturn(tenantManager);

        SAMLSSOUtil.setRealmService(realmService);

        Property property = new Property();
        property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
        property.setValue(TestConstants.LOACALHOST_DOMAIN);
        Property[] properties = {property};
        when(federatedAuthenticatorConfig.getProperties()).thenReturn(properties);
        when(federatedAuthenticatorConfig.getName()).thenReturn(
                IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
        FederatedAuthenticatorConfig[] fedAuthConfs = {federatedAuthenticatorConfig};
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(fedAuthConfs);

        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(anyString())).thenReturn(identityProvider);
    }
}
