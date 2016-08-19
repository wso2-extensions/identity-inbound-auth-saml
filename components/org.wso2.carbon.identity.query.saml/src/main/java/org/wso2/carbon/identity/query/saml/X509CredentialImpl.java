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

import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialContextSet;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;

/**
 * X509Credential implementation for signature verification of self issued tokens. The key is
 * constructed from modulus and exponent
 */
public class X509CredentialImpl implements X509Credential {

    private PublicKey publicKey = null;
    private X509Certificate signingCert = null;

    /**
     * Constructor.The key is constructed form modulus and exponent.
     *
     * @param modulus        modules number
     * @param publicExponent public exponent number
     * @throws NoSuchAlgorithmException If algorithm mismatch
     * @throws InvalidKeySpecException  If invalid key specification
     */
    public X509CredentialImpl(BigInteger modulus, BigInteger publicExponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        publicKey = keyFactory.generatePublic(spec);
    }

    /**
     * Constructor
     *
     * @param cert certificate of the source
     */
    public X509CredentialImpl(X509Certificate cert) {
        publicKey = cert.getPublicKey();
        signingCert = cert;
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
     * getter of public key
     *
     * @return PublicKey public key
     */
    @Nullable
    public PublicKey getPublicKey() {
        return publicKey;
    }


    @Nullable
    public PrivateKey getPrivateKey() {
        return null;
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
     * getter of Signature Certificate
     *
     * @return X509Certificate signature certificate
     */
    public X509Certificate getSigningCert() {
        return signingCert;
    }

    @Nonnull
    public X509Certificate getEntityCertificate() {
        return signingCert;
    }

    /**
     * getter of entity certificate chain
     *
     * @return List collection of certificates
     */
    @Nonnull
    public Collection<X509Certificate> getEntityCertificateChain() {

        return new ArrayList<X509Certificate>();
    }

    @Nullable
    public Collection<X509CRL> getCRLs() {

        return null;
    }


}
