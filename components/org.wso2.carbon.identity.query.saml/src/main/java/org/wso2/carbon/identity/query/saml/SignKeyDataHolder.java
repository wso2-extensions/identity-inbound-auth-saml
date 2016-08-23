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

package org.wso2.carbon.identity.query.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialContextSet;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.security.keystore.KeyStoreAdmin;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * This class is used to process Signature by loading algorithms, certificates,
 * private key, public key and etc
 */
public class SignKeyDataHolder implements X509Credential {

    public static final String SECURITY_KEY_STORE_KEY_ALIAS = "Security.KeyStore.KeyAlias";
    private final static Log log = LogFactory.getLog(SignKeyDataHolder.class);
    private static final String DSA_ENCRYPTION_ALGORITHM = "DSA";
    private String signatureAlgorithm = null;
    private X509Certificate[] issuerCerts = null;
    private PrivateKey issuerPK = null;
    private PublicKey publicKey = null;

    /**
     * This constructor is used to collect certificate information of the signature
     *
     * @param tenantDomain String type of tenant domain
     * @throws IdentityException If unable connect with RealmService
     */
    public SignKeyDataHolder(String tenantDomain) throws IdentityException {
        String keyAlias;
        KeyStoreAdmin keyAdmin;
        KeyStoreManager keyMan;
        Certificate[] certificates;
        int tenantID;

        try {

            if (tenantDomain == null) {
                tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            }

            tenantID = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);

            IdentityTenantUtil.initializeRegistry(tenantID, tenantDomain);

            if (tenantID != MultitenantConstants.SUPER_TENANT_ID) {
                String keyStoreName = SAMLSSOUtil.generateKSNameFromDomainName(tenantDomain);
                keyAlias = tenantDomain;
                keyMan = KeyStoreManager.getInstance(tenantID);
                KeyStore keyStore = keyMan.getKeyStore(keyStoreName);
                issuerPK = (PrivateKey) keyMan.getPrivateKey(keyStoreName, tenantDomain);
                certificates = keyStore.getCertificateChain(keyAlias);
                issuerCerts = new X509Certificate[certificates.length];

                int i = 0;
                for (Certificate certificate : certificates) {
                    issuerCerts[i++] = (X509Certificate) certificate;
                }

                signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA;

                publicKey = issuerCerts[0].getPublicKey();
                String pubKeyAlgo = publicKey.getAlgorithm();
                if (DSA_ENCRYPTION_ALGORITHM.equalsIgnoreCase(pubKeyAlgo)) {
                    signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
                }

            } else {
                keyAlias = ServerConfiguration.getInstance().getFirstProperty(
                        SECURITY_KEY_STORE_KEY_ALIAS);

                keyAdmin = new KeyStoreAdmin(tenantID,
                        SAMLSSOUtil.getRegistryService().getGovernanceSystemRegistry());
                keyMan = KeyStoreManager.getInstance(tenantID);

                issuerPK = (PrivateKey) keyAdmin.getPrivateKey(keyAlias, true);

                certificates = keyMan.getPrimaryKeyStore().getCertificateChain(keyAlias);

                issuerCerts = new X509Certificate[certificates.length];

                int i = 0;
                for (Certificate certificate : certificates) {
                    issuerCerts[i++] = (X509Certificate) certificate;
                }

                signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA;

                publicKey = issuerCerts[0].getPublicKey();
                String pubKeyAlgo = publicKey.getAlgorithm();
                if (DSA_ENCRYPTION_ALGORITHM.equalsIgnoreCase(pubKeyAlgo)) {
                    signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
                }
            }

        } catch (IdentityException e) {
            log.error("Unable to access realm service ", e);

        } catch (Exception e) {
            log.error("Signature processing failed ", e);

        }

    }

    /**
     * getter of the SignatureAlgorithm
     *
     * @return String Signature Algorithm
     */
    public String getSignatureAlgorithm() {

        return signatureAlgorithm;
    }

    /**
     * setter of Signature Algorithm
     *
     * @param signatureAlgorithm signature algorithm
     */
    public void setSignatureAlgorithm(String signatureAlgorithm) {

        this.signatureAlgorithm = signatureAlgorithm;
    }


    @Nullable
    public String getEntityId() {

        return null;
    }

    @Nullable
    public UsageType getUsageType() {

        return null;
    }


    public Collection<String> getKeyNames() {
        return null;
    }

    /**
     * This method is used to get Public Key
     *
     * @return PublicKey public key
     */
    @Nullable
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * This method is used to get PrivateKey
     *
     * @return PrivateKey private key
     */
    @Nullable
    public PrivateKey getPrivateKey() {

        return issuerPK;
    }

    @Nullable
    public SecretKey getSecretKey() {
        return null;
    }

    @Nullable
    public CredentialContextSet getCredentialContextSet() {

        return null;
    }


    public Class<? extends Credential> getCredentialType() {

        return null;
    }

    /**
     * This method is used to get Issuer Certificate
     *
     * @return X509Certificate certificate of issuer
     */
    @Nonnull
    public X509Certificate getEntityCertificate() {
        return issuerCerts[0];
    }


    public Collection<X509Certificate> getEntityCertificateChain() {

        return null;
    }

    @Nullable
    public Collection<X509CRL> getCRLs() {

        return null;
    }
}

