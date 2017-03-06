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

import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.identity.common.base.exception.IdentityRuntimeException;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;

/**
 * Class that will encapsulate the key store management functionality of a carbon instance.
 */
public class KeyStoreManager {

    private static volatile KeyStoreManager instance = new KeyStoreManager();
    private KeyStore serverKeyStore = null;


    private KeyStoreManager() {
        this.initKeyStore();
    }

    public static KeyStoreManager getInstance() {
        return instance;
    }

    private KeyStore initKeyStore() {

        String keyStorePath = KeyStoreConfig.getInstance().getKeyStoreLocation();
        String keyStorePassword = KeyStoreConfig.getInstance().getKeyStorePassword();
        String keyStoreType = KeyStoreConfig.getInstance().getKeyStoreType();

        if (this.serverKeyStore == null) {
            FileInputStream in = null;
            try {
                KeyStore store = KeyStore.getInstance(keyStoreType);
                in = new FileInputStream(keyStorePath);
                store.load(in, keyStorePassword.toCharArray());
                this.serverKeyStore = store;
            } catch (Exception e) {
                throw new SecurityException("Error while reading keystore from the given path.");
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException e) {
                        throw new SecurityException("Error while reading keystore.");
                    }
                }
            }
        }
        return this.serverKeyStore;
    }


    public X509Credential getX509Credential() {


        X509Credential credential;
        java.security.cert.X509Certificate cert;
        try {
            cert = (java.security.cert.X509Certificate) serverKeyStore.getCertificate(
                    KeyStoreConfig.getInstance().getKeyStoreAlias());
        } catch (KeyStoreException e) {
            throw new IdentityRuntimeException("Error while reading certificate from server keystore for alias " +
                                               KeyStoreConfig.getInstance().getKeyStoreAlias() + ".");
        }
        credential = new X509CredentialImpl(cert);
        return credential;
    }

    public PrivateKey getPrivateKey() {

        String alias = KeyStoreConfig.getInstance().getKeyStoreAlias();
        String keyStorePassword = KeyStoreConfig.getInstance().getKeyStorePassword();
        try {
            return (PrivateKey) serverKeyStore.getKey(alias, keyStorePassword.toCharArray());
        } catch (Exception e) {
            throw new IdentityRuntimeException("Error occurred while loading the key for the given alias " + alias);
        }
    }
}
