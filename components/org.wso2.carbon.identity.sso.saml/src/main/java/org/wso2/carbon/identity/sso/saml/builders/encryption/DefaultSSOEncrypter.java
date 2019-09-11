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
package org.wso2.carbon.identity.sso.saml.builders.encryption;

import net.shibboleth.utilities.java.support.xml.NamespaceSupport;
import org.apache.xml.security.utils.Base64;
// import org.opensaml.Configuration;  Previous Version (New Version Below)
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.security.crypto.KeySupport;
// import org.opensaml.xmlsec.EncryptionParameters;  Previous Version (New Version Below)
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
// import org.opensaml.xml.security.SecurityHelper;  Previous Version (New Version CredentialSupport, KeySupport)
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoGenerator;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.builders.X509CredentialImpl;

import javax.xml.namespace.QName;
import java.security.cert.CertificateEncodingException;

public class DefaultSSOEncrypter implements SSOEncrypter {
    @Override
    public void init() throws IdentityException {
        //Overridden method, no need to implement the body
    }

    @Override
    public EncryptedAssertion doEncryptedAssertion(Assertion assertion, X509Credential cred, String alias, String encryptionAlgorithm) throws IdentityException {
        try {

            Credential symmetricCredential = CredentialSupport.getSimpleCredential(
                    KeySupport.generateKey(JCAConstants.KEY_ALGO_AES,
                            256,null));


            DataEncryptionParameters encParams = new DataEncryptionParameters();
            encParams.setAlgorithm(IdentityApplicationManagementUtil
                    .getAssertionEncryptionAlgorithmURIByConfig());
            encParams.setEncryptionCredential(symmetricCredential);

            KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
            keyEncryptionParameters.setAlgorithm(IdentityApplicationManagementUtil
                    .getKeyEncryptionAlgorithmURIByConfig());
            keyEncryptionParameters.setEncryptionCredential(cred);

            Encrypter encrypter = new Encrypter(encParams, keyEncryptionParameters);
            encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

            EncryptedAssertion encrypted = encrypter.encrypt(assertion);
            NamespaceSupport.appendNamespaceDeclaration(encrypted.getEncryptedData().getKeyInfo().
                    getEncryptedKeys().get(0).getEncryptionMethod().getOrderedChildren().
                    get(0).getDOM(), "http://www.w3.org/2000/09/xmldsig#", "ds");
            return encrypted;
        } catch (Exception e) {
            throw IdentityException.error("Error while Encrypting Assertion", e);
        }
    }

    @Override
    public EncryptedAssertion doEncryptedAssertion(Assertion assertion, X509Credential cred, String alias, String
            assertionEncryptionAlgorithm, String keyEncryptionAlgorithm) throws IdentityException {
        try {

            Credential symmetricCredential = CredentialSupport.getSimpleCredential(
                    KeySupport.generateKey(JCAConstants.KEY_ALGO_AES,
                            256,null));

            DataEncryptionParameters encParams = new DataEncryptionParameters();
            encParams.setAlgorithm(assertionEncryptionAlgorithm);
            encParams.setEncryptionCredential(symmetricCredential);

            KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
            keyEncryptionParameters.setAlgorithm(keyEncryptionAlgorithm);
            keyEncryptionParameters.setEncryptionCredential(cred);

            KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
            X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);

            String value;
            try {
                value = Base64.encode(((X509CredentialImpl) cred).getSigningCert().getEncoded());
            } catch (CertificateEncodingException e) {
                throw IdentityException.error("Error occurred while retrieving encoded cert", e);
            }

            cert.setValue(value);
            data.getX509Certificates().add(cert);
            keyInfo.getX509Datas().add(data);

            keyEncryptionParameters.setKeyInfoGenerator(new StaticKeyInfoGenerator(keyInfo));

            Encrypter encrypter = new Encrypter(encParams, keyEncryptionParameters);
            encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

            EncryptedAssertion encrypted = encrypter.encrypt(assertion);
            NamespaceSupport.appendNamespaceDeclaration(encrypted.getEncryptedData().getKeyInfo().
                            getEncryptedKeys().get(0).getEncryptionMethod().getOrderedChildren().
                            get(0).getDOM(), "http://www.w3.org/2000/09/xmldsig#", "ds");
            return encrypted;
        } catch (Exception e) {
            throw IdentityException.error("Error while Encrypting Assertion", e);
        }
    }

    /**
     * Builds SAML Elements
     *
     * @param objectQName
     * @return
     * @throws IdentityException
     */
    private XMLObject buildXMLObject(QName objectQName) throws IdentityException {

        XMLObjectBuilder builder = XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(objectQName);
        if (builder == null) {
            throw IdentityException.error("Unable to retrieve builder for object QName " + objectQName);
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
    }
}
