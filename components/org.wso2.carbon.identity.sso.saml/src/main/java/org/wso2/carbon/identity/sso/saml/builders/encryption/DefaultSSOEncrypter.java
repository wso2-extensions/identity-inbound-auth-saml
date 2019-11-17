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

import org.apache.xml.security.utils.Base64;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoGenerator;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import net.shibboleth.utilities.java.support.xml.NamespaceSupport;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.builders.X509CredentialImpl;

import javax.xml.namespace.QName;
import java.security.cert.CertificateEncodingException;
import java.util.List;

public class DefaultSSOEncrypter implements SSOEncrypter {

    private static final String prefix = "ds";

    @Override
    public void init() throws IdentityException {
        //Overridden method, no need to implement the body
    }

    @Override
    public EncryptedAssertion doEncryptedAssertion(Assertion assertion, X509Credential cred, String alias, String encryptionAlgorithm) throws IdentityException {

        try {

            String keyAlgorithm = AlgorithmSupport.getKeyAlgorithm(IdentityApplicationManagementUtil
                    .getAssertionEncryptionAlgorithmURIByConfig());
            Integer keyAlgorithmKeyLength = AlgorithmSupport.getKeyLength(IdentityApplicationManagementUtil
                    .getAssertionEncryptionAlgorithmURIByConfig());
            Credential symmetricCredential;

            if (keyAlgorithm != null && keyAlgorithmKeyLength != null) {
                symmetricCredential = CredentialSupport.getSimpleCredential(
                        KeySupport.generateKey(keyAlgorithm, keyAlgorithmKeyLength, null));
            } else {
                throw new IdentityException("Invalid assertion encryption algorithm");
            }

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
            appendNamespaceDeclaration(encrypted);

            return encrypted;
        } catch (Exception e) {
            throw IdentityException.error("Error while Encrypting Assertion", e);
        }
    }

    @Override
    public EncryptedAssertion doEncryptedAssertion(Assertion assertion, X509Credential cred, String alias, String
            assertionEncryptionAlgorithm, String keyEncryptionAlgorithm) throws IdentityException {

        try {

            String keyAlgorithm = AlgorithmSupport.getKeyAlgorithm(assertionEncryptionAlgorithm);
            Integer keyAlgorithmKeyLength = AlgorithmSupport.getKeyLength(assertionEncryptionAlgorithm);
            Credential symmetricCredential;

            if (keyAlgorithm != null && keyAlgorithmKeyLength != null) {
                symmetricCredential = CredentialSupport.getSimpleCredential(
                        KeySupport.generateKey(keyAlgorithm, keyAlgorithmKeyLength, null));
            } else {
                throw new IdentityException("Invalid assertion encryption algorithm");
            }

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
            appendNamespaceDeclaration(encrypted);

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

    /**
     * The process below will append a namespace declaration to the encrypted assertion.
     * This is executed due to the fact that one of the attributes required does not get
     * set automatically in OpenSAML 3 as in OpenSAML 2. If this process is skipped then
     * an error will be thrown when decrypting the assertion.
     *
     * @param encryptedAssertion The encrypted assertion.
     * @throws IdentityException If the namespace declaration cannot be set.
     */
    private void appendNamespaceDeclaration(EncryptedAssertion encryptedAssertion) throws IdentityException {

        Boolean isNamespaceSet = false;
        String errorMessage = "Failed to set Namespace Declaration";

        if (encryptedAssertion.getEncryptedData().getKeyInfo() != null &&
                encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().size() > 0) {

            List<EncryptedKey> encryptedKeys = encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys();

            for (EncryptedKey encryptedKey : encryptedKeys) {
                if (encryptedKey.getEncryptionMethod() != null && encryptedKey.getEncryptionMethod().hasChildren()) {
                    for (XMLObject encryptedKeyChildElement : encryptedKey.getEncryptionMethod().getOrderedChildren()) {
                        if (encryptedKeyChildElement.getElementQName().getLocalPart().equals("DigestMethod")) {
                            if (encryptedKeyChildElement.getDOM() != null) {
                                NamespaceSupport.appendNamespaceDeclaration(encryptedKeyChildElement.getDOM(), SignatureConstants.XMLSIG_NS, prefix);
                                isNamespaceSet = true;
                            }
                        }
                    }
                }
            }

            if (!isNamespaceSet) {
                throw new IdentityException(errorMessage);
            }

        } else {
            throw new IdentityException(errorMessage);
        }
    }
}
