/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.auth.saml2.common;

import org.apache.commons.collections.CollectionUtils;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialContextSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.X509Credential;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import javax.crypto.SecretKey;

/**
 * X509Credential implementation for signing and verification.
 */
public class X509CredentialImpl implements X509Credential {

    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;
    private X509Certificate entityCertificate = null;

    public X509CredentialImpl(X509Certificate certificate) {

        entityCertificate = certificate;
        publicKey = certificate.getPublicKey();
    }

    public X509CredentialImpl(X509Certificate certificate, PrivateKey privateKey) {

        this.entityCertificate = certificate;
        this.publicKey = certificate.getPublicKey();
        this.privateKey = privateKey;
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

    // ********** Not implemented **************************************************************
    @Override
    public Collection<X509CRL> getCRLs() {
        return CollectionUtils.EMPTY_COLLECTION;
    }

    @Override
    public Collection<X509Certificate> getEntityCertificateChain() {
        Collection<X509Certificate> certificates = new ArrayList();
        certificates.add(entityCertificate);
        return certificates;
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
        return Collections.emptySet();
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
