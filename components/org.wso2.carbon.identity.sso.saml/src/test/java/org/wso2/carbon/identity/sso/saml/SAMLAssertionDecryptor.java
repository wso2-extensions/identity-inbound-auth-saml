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

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialContextSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.X509Credential;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Helper class for decrypting encrypted assertions.
 */
public class SAMLAssertionDecryptor {

    public static Assertion getDecryptedAssertion(EncryptedAssertion encryptedAssertion) throws DecryptionException,
            KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {

        KeyStore keyStore = TestUtils.loadKeyStoreFromFileSystem(TestUtils.getFilePath(TestConstants.KEY_STORE_NAME),
                TestConstants.WSO2_CARBON, "JKS");
        DecryptorX509KeyStoreCredential decryptorX509KeyStoreCredential = new DecryptorX509KeyStoreCredential(keyStore,
                TestConstants.WSO2_CARBON, TestConstants.WSO2_CARBON, TestConstants.WSO2_CARBON.toCharArray());

        KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(decryptorX509KeyStoreCredential);

        EncryptedKey key = encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0);
        Decrypter decrypter = new Decrypter(null, keyResolver, null);
        SecretKey dkey = (SecretKey) decrypter.decryptKey(key, encryptedAssertion.getEncryptedData().
                getEncryptionMethod().getAlgorithm());
        Credential shared = SecurityHelper.getSimpleCredential(dkey);
        decrypter = new Decrypter(new StaticKeyInfoCredentialResolver(shared), null, null);
        decrypter.setRootInNewDocument(true);
        return decrypter.decrypt(encryptedAssertion);
    }

    public static class DecryptorX509KeyStoreCredential implements X509Credential {

        private PublicKey publicKey = null;
        private PrivateKey privateKey = null;
        private X509Certificate entityCertificate = null;

        public DecryptorX509KeyStoreCredential(KeyStore keyStore, String publicCertAlias, String privateKeyAlias,
                                               char[] privateKeyPassword) throws KeyStoreException,
                UnrecoverableKeyException, NoSuchAlgorithmException {

            readX509Credentials(keyStore, publicCertAlias, privateKeyAlias, privateKeyPassword);
        }

        public DecryptorX509KeyStoreCredential(InputStream keyStoreInputStream, char[] keyStorePassword,
                                               String publicCertAlias, String privateKeyAlias,
                                               char[] privateKeyPassword) throws UnrecoverableKeyException,
                CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {

            readX509Credentials(keyStoreInputStream, keyStorePassword, publicCertAlias,
                    privateKeyAlias, privateKeyPassword);
        }

        protected void readX509Credentials(KeyStore keyStore, String publicCertAlias, String privateKeyAlias,
                                           char[] privateKeyPassword) throws KeyStoreException,
                UnrecoverableKeyException, NoSuchAlgorithmException {

            entityCertificate = (X509Certificate) keyStore.getCertificate(publicCertAlias);
            publicKey = entityCertificate.getPublicKey();
            privateKey = (PrivateKey) keyStore.getKey(privateKeyAlias, privateKeyPassword);
        }

        protected void readX509Credentials(InputStream keyStoreInputStream, char[] keyStorePassword,
                                           String publicCertAlias, String privateKeyAlias, char[] privateKeyPassword)
                throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
                UnrecoverableKeyException {

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreInputStream, keyStorePassword);
            readX509Credentials(keyStore, publicCertAlias, privateKeyAlias, privateKeyPassword);
            if (keyStoreInputStream != null) {
                keyStoreInputStream.close();
            }
        }

        @Override
        public PublicKey getPublicKey() {
            return publicKey;
        }

        @Override
        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        @Override
        public X509Certificate getEntityCertificate() {
            return entityCertificate;
        }

        // ********** Not implemented ************************************************************** //

        @Override
        public Collection<X509CRL> getCRLs() {
            return new ArrayList<X509CRL>();
        }

        @Override
        public Collection<X509Certificate> getEntityCertificateChain() {
            return new ArrayList<X509Certificate>();
        }

        @Override
        public CredentialContextSet getCredentalContextSet() {
            return null;
        }

        @Override
        public Class<? extends Credential> getCredentialType() {
            return null;
        }

        @Override
        public String getEntityId() {
            return null;
        }

        @Override
        public Collection<String> getKeyNames() {
            return new ArrayList<String>();
        }

        @Override
        public SecretKey getSecretKey() {
            return null;
        }

        @Override
        public UsageType getUsageType() {
            return null;
        }
    }
}
