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

package org.wso2.carbon.identity.sso.saml.builders;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialContextSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collection;
import java.util.Collections;
import javax.crypto.SecretKey;

/**
 * X509Credential implementation for signature verification of self issued tokens. The key is
 * constructed from modulus and exponent
 */
public class X509CredentialImpl implements X509Credential {

    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;
    private X509Certificate signingCert = null;

    private static KeyStore superTenantSignKeyStore = null;

    private static Log log = LogFactory.getLog(X509CredentialImpl.class);

    public static final String SECURITY_SAML_SIGN_KEY_STORE_LOCATION = "Security.SAMLSignKeyStore.Location";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_TYPE = "Security.SAMLSignKeyStore.Type";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_PASSWORD = "Security.SAMLSignKeyStore.Password";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS = "Security.SAMLSignKeyStore.KeyAlias";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD = "Security.SAMLSignKeyStore.KeyPassword";

    /**
     * Instantiates X509Credential.
     * This credential object will hold the private key, public key and the cert for the respective tenant domain.
     *
     * @param tenantDomain tenant domain
     */
    public X509CredentialImpl(String tenantDomain) throws IdentityException {

        X509Certificate cert = null;
        int tenantId = 0;

        try {
            tenantId = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
        } catch (UserStoreException e) {
            throw new IdentityException("Exception occurred while retrieving Tenant ID from tenant domain " +
                    tenantDomain, e);
        }

        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
        PrivateKey key = null;

        try {
            // Get the private key and the cert for the respective tenant domain.
            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name.
                String ksName = tenantDomain.trim().replace(".", "-");
                // derive JKS name.
                String jksName = ksName + ".jks";
                key = (PrivateKey) keyStoreManager.getPrivateKey(jksName, tenantDomain);
                cert = (X509Certificate) keyStoreManager.getKeyStore(jksName)
                        .getCertificate(tenantDomain);
            } else {
                if (isSignKeyStoreConfigured()) {
                    if (log.isDebugEnabled()) {
                        log.debug("Initializing Key Data for super tenant using separate sign key store.");
                    }

                    try {
                        if (superTenantSignKeyStore == null) {
                            String keyStoreLocation = ServerConfiguration.getInstance().getFirstProperty(
                                    SECURITY_SAML_SIGN_KEY_STORE_LOCATION);
                            try (FileInputStream is = new FileInputStream(keyStoreLocation)) {
                                String keyStoreType = ServerConfiguration.getInstance().getFirstProperty(
                                        SECURITY_SAML_SIGN_KEY_STORE_TYPE);
                                KeyStore keyStore = KeyStore.getInstance(keyStoreType);

                                char[] keyStorePassword = ServerConfiguration.getInstance().getFirstProperty(
                                        SECURITY_SAML_SIGN_KEY_STORE_PASSWORD).toCharArray();
                                keyStore.load(is, keyStorePassword);

                                superTenantSignKeyStore = keyStore;
                            } catch (FileNotFoundException e) {
                                throw new IdentityException("Unable to locate keystore.", e);
                            } catch (IOException e) {
                                throw new IdentityException("Unable to read keystore.", e);
                            } catch (CertificateException e) {
                                throw new IdentityException("Unable to read certificate.", e);
                            }
                        }

                        String keyAlias = ServerConfiguration.getInstance().getFirstProperty(
                                SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS);
                        char[] keyPassword = ServerConfiguration.getInstance().getFirstProperty(
                                SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD).toCharArray();
                        Key privateKey = superTenantSignKeyStore.getKey(keyAlias, keyPassword);

                        Certificate publicKey = superTenantSignKeyStore.getCertificate(keyAlias);

                        if (privateKey instanceof PrivateKey) {
                            key = (PrivateKey) privateKey;
                        } else {
                            throw new IdentityException("Configured signing KeyStore private key is invalid.");
                        }

                        if (publicKey instanceof X509Certificate) {
                            cert = (X509Certificate) publicKey;
                        } else {
                            throw new IdentityException("Configured signing KeyStore public key is invalid.");
                        }

                    } catch (NoSuchAlgorithmException e) {
                        throw new IdentityException("Unable to load algorithm", e);
                    } catch (UnrecoverableKeyException e) {
                        throw new IdentityException("Unable to load key", e);
                    } catch (KeyStoreException e) {
                        throw new IdentityException("Unable to load keystore", e);
                    }
                } else {
                    key = keyStoreManager.getDefaultPrivateKey();
                    cert = keyStoreManager.getDefaultPrimaryCertificate();
                }
            }
        } catch (Exception e) {
            throw new IdentityException("Error retrieving private key and the certificate for tenant " +
                    tenantDomain, e);
        }

        if (key == null) {
            throw new IdentityException("Cannot find the private key for tenant " + tenantDomain);
        }

        this.privateKey = key;

        if (cert == null) {
            throw new IdentityException("Cannot find the certificate.");
        }

        signingCert = cert;
        publicKey = cert.getPublicKey();
    }

    /**
     * Check whether separate configurations for sign KeyStore available.
     *
     * @return true if necessary configurations are defined for sign KeyStore; false otherwise.
     */
    private boolean isSignKeyStoreConfigured() {

        String keyStoreLocation = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_LOCATION);
        String keyStoreType = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_TYPE);
        String keyStorePassword = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_PASSWORD);
        String keyAlias = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS);
        String keyPassword = ServerConfiguration.getInstance().getFirstProperty(
                SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD);

        return StringUtils.isNotBlank(keyStoreLocation) && StringUtils.isNotBlank(keyStoreType)
                && StringUtils.isNotBlank(keyStorePassword) && StringUtils.isNotBlank(keyAlias)
                && StringUtils.isNotBlank(keyPassword);
    }

    /**
     * The key is constructed form modulus and exponent.
     *
     * @param modulus
     * @param publicExponent
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public X509CredentialImpl(BigInteger modulus, BigInteger publicExponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(spec);
    }

    public X509CredentialImpl(X509Certificate cert) {
        publicKey = cert.getPublicKey();
        signingCert = cert;
    }

    /**
     * Retrieves the publicKey
     */
    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    public X509Certificate getSigningCert() {
        return signingCert;
    }

    // ********** Not implemented **************************************************************

    @Override
    public X509Certificate getEntityCertificate() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Collection<X509CRL> getCRLs() {
        // TODO Auto-generated method stub
        return Collections.emptyList();
    }

    @Override
    public Collection<X509Certificate> getEntityCertificateChain() {
        // TODO Auto-generated method stub
        return Collections.emptyList();
    }

    @Override
    public CredentialContextSet getCredentalContextSet() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Class<? extends Credential> getCredentialType() {
        return X509Credential.class;
    }

    @Override
    public String getEntityId() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Collection<String> getKeyNames() {
        // TODO Auto-generated method stub
        return Collections.emptyList();
    }

    @Override
    public PrivateKey getPrivateKey() {

        return privateKey;
    }

    @Override
    public SecretKey getSecretKey() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public UsageType getUsageType() {
        // TODO Auto-generated method stub
        return null;
    }
}
