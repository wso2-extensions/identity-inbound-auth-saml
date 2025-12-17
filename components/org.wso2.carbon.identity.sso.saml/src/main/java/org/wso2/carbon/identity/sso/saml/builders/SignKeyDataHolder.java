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
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialContextSet;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.security.KeystoreUtils;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;


public class SignKeyDataHolder implements X509Credential {

    private static final String DSA_ENCRYPTION_ALGORITHM = "DSA";
    public static final String SECURITY_KEY_STORE_KEY_ALIAS = "Security.KeyStore.KeyAlias";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_LOCATION = "Security.SAMLSignKeyStore.Location";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_TYPE = "Security.SAMLSignKeyStore.Type";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_PASSWORD = "Security.SAMLSignKeyStore.Password";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS = "Security.SAMLSignKeyStore.KeyAlias";
    public static final String SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD = "Security.SAMLSignKeyStore.KeyPassword";

    private String signatureAlgorithm = null;
    private X509Certificate[] issuerCerts = null;
    private PrivateKey issuerPrivateKey = null;
    private static KeyStore superTenantSignKeyStore = null;

    private static final Log log = LogFactory.getLog(SignKeyDataHolder.class);

    public SignKeyDataHolder(String username) throws IdentityException {
        int tenantID;
        String tenantDomain = null;
        String userTenantDomain;
        String spTenantDomain;

        try {

            userTenantDomain = SAMLSSOUtil.getUserTenantDomain();
            spTenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

            if (userTenantDomain == null) {
                // all local authenticator must set the value of userTenantDomain.
                // if userTenantDomain is null that means, there is no local authenticator or
                // the assert with local ID is set. In that case, this should be coming from
                // federated authentication. In that case, we treat SP domain is equal to user domain.
                userTenantDomain = spTenantDomain;
            }

            if (!SAMLSSOUtil.isSaaSApplication() && !SAMLSSOUtil.isOrganizationLogin()
                    && !spTenantDomain.equalsIgnoreCase(userTenantDomain)) {
                throw IdentityException.error("Service Provider tenant domain must be equal to user tenant domain"
                        + " for non-SaaS applications");
            }

            String signWithValue = IdentityUtil.getProperty(
                    SAMLSSOConstants.FileBasedSPConfig.USE_AUTHENTICATED_USER_DOMAIN_CRYPTO);
            if (signWithValue != null && "true".equalsIgnoreCase(signWithValue.trim())) {
                tenantDomain = userTenantDomain;
                tenantID = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
            } else {
                tenantDomain = spTenantDomain;
                tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
            }

            IdentityTenantUtil.initializeRegistry(tenantID, tenantDomain);

            if (tenantID != MultitenantConstants.SUPER_TENANT_ID) {
                initializeKeyDataForTenant(tenantID, tenantDomain);
            } else {
                if (isSignKeyStoreConfigured()) {
                    initializeKeyDataForSuperTenantFromSignKeyStore();
                } else {
                    initializeKeyDataForSuperTenantFromSystemKeyStore();
                }
            }

        } catch (IdentityException e) {
            throw new IdentityException("Unable to access the realm service of the tenant domain:" + tenantDomain, e);
        } catch (KeyStoreException e) {
            throw new IdentityException("Unable to load keystore of the tenant domain:" + tenantDomain, e);
        } catch (UserStoreException e) {
            throw new IdentityException("Unable to load user store of the tenant domain:" + tenantDomain, e);
        } catch (Exception e) {
            throw new IdentityException("Unable to get primary keystore of the tenant domain:" + tenantDomain, e);
        }

    }

    /**
     * Set parameters needed for build Sign Key from the tenant KeyStore
     *
     * @param tenantID
     * @param tenantDomain
     * @throws Exception
     */
    private void initializeKeyDataForTenant(int tenantID, String tenantDomain) throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Initializing Key Data for tenant: " + tenantDomain);
        }

        String keyStoreName = SAMLSSOUtil.generateKSNameFromDomainName(tenantDomain);
        String keyAlias = tenantDomain;
        KeyStoreManager keyMan = KeyStoreManager.getInstance(tenantID);
        KeyStore keyStore = keyMan.getKeyStore(keyStoreName);
        issuerPrivateKey = (PrivateKey) keyMan.getPrivateKey(keyStoreName, tenantDomain);

        Certificate[] certificates = keyStore.getCertificateChain(keyAlias);
        issuerCerts = Arrays.copyOf(certificates, certificates.length, X509Certificate[].class);

        signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA;
        String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
        if (DSA_ENCRYPTION_ALGORITHM.equalsIgnoreCase(pubKeyAlgo)) {
            signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
        }
    }

    /**
     * Set parameters needed for build Sign Key from the Sign KeyStore which is defined under Security.KeyStore in
     * carbon.xml
     *
     * @throws Exception
     */
    private void initializeKeyDataForSuperTenantFromSystemKeyStore() throws Exception {
        if (log.isDebugEnabled()) {
            log.debug("Initializing Key Data for super tenant using system key store");
        }

        String keyAlias = ServerConfiguration.getInstance().getFirstProperty(SECURITY_KEY_STORE_KEY_ALIAS);
        if (StringUtils.isBlank(keyAlias)) {
            throw new IdentityException("Invalid file configurations. The key alias is not found.");
        }

        KeyStoreManager keyMan = KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID);
        issuerPrivateKey = keyMan.getDefaultPrivateKey();
        Certificate[] certificates = keyMan.getPrimaryKeyStore().getCertificateChain(keyAlias);
        issuerCerts = Arrays.copyOf(certificates, certificates.length, X509Certificate[].class);

        signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA;
        String pubKeyAlgo = issuerCerts[0].getPublicKey().getAlgorithm();
        if (DSA_ENCRYPTION_ALGORITHM.equalsIgnoreCase(pubKeyAlgo)) {
            signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
        }
    }

    /**
     * Check whether separate configurations for sign KeyStore available
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
     * Set parameters needed for build Sign Key from the Sign KeyStore which is defined under Security.SAMLSignKeyStore
     * in carbon.xml
     *
     * @throws IdentityException
     */
    private void initializeKeyDataForSuperTenantFromSignKeyStore() throws IdentityException {
        if (log.isDebugEnabled()) {
            log.debug("Initializing Key Data for super tenant using separate sign key store");
        }

        try {
            if (superTenantSignKeyStore == null) {

                String keyStoreLocation = ServerConfiguration.getInstance().getFirstProperty(
                        SECURITY_SAML_SIGN_KEY_STORE_LOCATION);
                try (FileInputStream is = new FileInputStream(keyStoreLocation)) {
                    String keyStoreType = ServerConfiguration.getInstance().getFirstProperty(
                            SECURITY_SAML_SIGN_KEY_STORE_TYPE);
                    KeyStore keyStore = KeystoreUtils.getKeystoreInstance(keyStoreType);

                    char[] keyStorePassword = ServerConfiguration.getInstance().getFirstProperty(
                            SECURITY_SAML_SIGN_KEY_STORE_PASSWORD).toCharArray();
                    keyStore.load(is, keyStorePassword);

                    superTenantSignKeyStore = keyStore;

                } catch (FileNotFoundException e) {
                    throw new IdentityException("Unable to locate keystore", e);
                } catch (IOException | NoSuchProviderException e) {
                    throw new IdentityException("Unable to read keystore", e);
                } catch (CertificateException e) {
                    throw new IdentityException("Unable to read certificate", e);
                }
            }

            String keyAlias = ServerConfiguration.getInstance().getFirstProperty(
                    SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS);
            char[] keyPassword = ServerConfiguration.getInstance().getFirstProperty(
                    SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD).toCharArray();
            Key key = superTenantSignKeyStore.getKey(keyAlias, keyPassword);

            if (key instanceof PrivateKey) {
                issuerPrivateKey = (PrivateKey) key;

                Certificate[] certificates = superTenantSignKeyStore.getCertificateChain(keyAlias);
                issuerCerts = Arrays.copyOf(certificates, certificates.length, X509Certificate[].class);

                signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA;
                Certificate cert = superTenantSignKeyStore.getCertificate(keyAlias);
                PublicKey publicKey = cert.getPublicKey();
                String pubKeyAlgo = publicKey.getAlgorithm();
                if (DSA_ENCRYPTION_ALGORITHM.equalsIgnoreCase(pubKeyAlgo)) {
                    signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
                }
            } else {
                throw new IdentityException("Configured signing KeyStore private key is invalid");
            }

        } catch (NoSuchAlgorithmException e) {
            throw new IdentityException("Unable to load algorithm", e);
        } catch (UnrecoverableKeyException e) {
            throw new IdentityException("Unable to load key", e);
        } catch (KeyStoreException e) {
            throw new IdentityException("Unable to load keystore", e);
        }
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public Collection<X509CRL> getCRLs() {
        return Collections.emptyList();
    }

    @Override
    public X509Certificate getEntityCertificate() {
        return issuerCerts[0];
    }

    @Override
    public Collection<X509Certificate> getEntityCertificateChain() {
        return Arrays.asList(issuerCerts);
    }

    /***
     * Get the credential context set.
     * @return This method is not supported so, the return is null.
     */
    @Override
    public CredentialContextSet getCredentialContextSet() {
        return null;
    }

    @Override
    public Class<? extends Credential> getCredentialType() {
        // TODO Auto-generated method stub
        return null;
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
        return issuerPrivateKey;
    }

    @Override
    public PublicKey getPublicKey() {
        return issuerCerts[0].getPublicKey();
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

