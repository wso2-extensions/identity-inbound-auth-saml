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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.*;
import org.wso2.carbon.identity.sso.saml.builders.X509CredentialImpl;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.security.Security;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;

/**
 * Unit tests for SAML request encryption functionality.
 */
public class EncryptionTests {

    @Mock
    private RealmService realmService;

    @Mock
    private TenantManager tenantManager;

    @Mock
    private KeyStoreManager keyStoreManager;

    @Mock
    private X509CredentialImpl x509Credential;

    private AutoCloseable openMocks;
    private MockedStatic<KeyStoreManager> keyStoreManagerStatic;
    private MockedStatic<IdentityUtil> identityUtilStatic;
    private MockedStatic<FrameworkServiceComponent> frameworkServiceComponentStatic;

    @BeforeMethod
    public void init() {
        openMocks = MockitoAnnotations.openMocks(this);
    }

    @AfterMethod
    public void cleanup() throws Exception {
        if (frameworkServiceComponentStatic != null) frameworkServiceComponentStatic.close();
        if (identityUtilStatic != null) identityUtilStatic.close();
        if (keyStoreManagerStatic != null) keyStoreManagerStatic.close();
        if (openMocks != null) openMocks.close();
        Mockito.framework().clearInlineMocks();
    }

    @Test
    public void testSetEncryptedAssertionWithKeyEncryptionAlgorithm() throws Exception {

        // This is done to avoid info logs which represent "Algorithm not registered"
        Security.addProvider(new BouncyCastleProvider());

        Assertion assertion = SAMLTestAssertionBuilder.buildDefaultSAMLAssertion();
        prepareForAssertionEncryption();
        frameworkServiceComponentStatic = Mockito.mockStatic(FrameworkServiceComponent.class);
        frameworkServiceComponentStatic.when(FrameworkServiceComponent::getRealmService).thenReturn(realmService);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(anyString())).thenReturn(-1234);
        EncryptedAssertion encryptedAssertion = SAMLSSOUtil.setEncryptedAssertion(assertion,
                TestConstants.ASSERTION_ENCRYPTION_ALGO, TestConstants.KEY_ENCRYPTION_ALGO, TestConstants.WSO2_CARBON,
                "carbon.super");

        TestUtils.prepareCredentials(x509Credential);
        Assertion decryptedAssertion = TestUtils.getDecryptedAssertion(encryptedAssertion, x509Credential);

        assertEncryptedSAMLAssertion(assertion, encryptedAssertion, decryptedAssertion);
    }

    @Test
    public void testSetEncryptedAssertionWithNoKeyEncryptionAlgorithm() throws Exception{

        // This is done to avoid info logs which represent "Algorithm not registered"
        Security.addProvider(new BouncyCastleProvider());

        Assertion assertion = SAMLTestAssertionBuilder.buildDefaultSAMLAssertion();
        prepareForAssertionEncryption();
        frameworkServiceComponentStatic = Mockito.mockStatic(FrameworkServiceComponent.class);
        frameworkServiceComponentStatic.when(FrameworkServiceComponent::getRealmService).thenReturn(realmService);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(anyString())).thenReturn(-1234);
        EncryptedAssertion encryptedAssertion = SAMLSSOUtil.setEncryptedAssertion(assertion, TestConstants
                .ASSERTION_ENCRYPTION_ALGO, TestConstants.WSO2_CARBON, "carbon.super");

        TestUtils.prepareCredentials(x509Credential);
        Assertion decryptedAssertion = TestUtils.getDecryptedAssertion(encryptedAssertion, x509Credential);

        assertEncryptedSAMLAssertion(assertion, encryptedAssertion, decryptedAssertion);
    }

    private void assertEncryptedSAMLAssertion(Assertion assertion, EncryptedAssertion encryptedAssertion,
                                              Assertion decryptedAssertion) throws Exception {

        assertEquals(encryptedAssertion.getEncryptedData().getEncryptionMethod().getAlgorithm(),
                TestConstants.ASSERTION_ENCRYPTION_ALGO, "Encrypted SAML assertion should contain the given " +
                        "encryption algorithm.");
        assertEquals(decryptedAssertion.getIssuer().getValue(), assertion.getIssuer().getValue(), "Issuer should be " +
                "the same in both decrypted SAML assertion and original SAML assertion.");
        assertEquals(decryptedAssertion.getSubject().getNameID().getValue(),
                assertion.getSubject().getNameID().getValue(), "Subject should be the same in both decrypted SAML " +
                        "assertion and original SAML assertion.");
        assertEquals(decryptedAssertion.getAttributeStatements().size(), assertion.getAttributeStatements().size(),
                "Attribute statements size should be the same in both decrypted SAML assertion and original SAML " +
                        "assertion.");
        assertEquals(decryptedAssertion.getAuthnStatements().get(0).getSessionIndex(),
                assertion.getAuthnStatements().get(0).getSessionIndex(), "SessionId should be the same in both " +
                        "decrypted SAML assertion and original SAML assertion.");
    }

    private void prepareForAssertionEncryption() throws Exception {

        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(anyString())).thenReturn(4567);
        keyStoreManagerStatic = Mockito.mockStatic(KeyStoreManager.class);
        keyStoreManagerStatic.when(() -> KeyStoreManager.getInstance(anyInt())).thenReturn(keyStoreManager);
        when(keyStoreManager.getKeyStore(anyString())).thenReturn(TestUtils.loadKeyStoreFromFileSystem(
                TestUtils.getFilePath(TestConstants.KEY_STORE_NAME), TestConstants.WSO2_CARBON, "JKS"));
        when(keyStoreManager.getPrimaryKeyStore()).thenReturn(TestUtils.loadKeyStoreFromFileSystem(
                TestUtils.getFilePath(TestConstants.KEY_STORE_NAME), TestConstants.WSO2_CARBON, "JKS"));
        SAMLSSOUtil.setRealmService(realmService);

        identityUtilStatic = Mockito.mockStatic(IdentityUtil.class);
        identityUtilStatic.when(() -> IdentityUtil.getProperty(SAMLSSOConstants.SAML_SSO_ENCRYPTOR_CONFIG_PATH)).thenReturn(
                TestConstants.DEFAULT_SSO_ENCRYPTOR);
    }

}
