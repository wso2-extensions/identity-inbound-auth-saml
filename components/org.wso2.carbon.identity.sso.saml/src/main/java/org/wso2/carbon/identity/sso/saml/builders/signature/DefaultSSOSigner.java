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
package org.wso2.carbon.identity.sso.saml.builders.signature;

import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.wso2.carbon.identity.base.IdentityException;

import javax.xml.namespace.QName;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

public class DefaultSSOSigner implements SSOSigner {

    @Override
    public void init() throws IdentityException {
        //Overridden method, no need to implement the body
    }

    @Override
    public boolean validateXMLSignature(RequestAbstractType request, X509Credential cred,
                                        String alias) throws IdentityException {
        return validateXMLSignature((SignableXMLObject) request, cred, alias);
    }

    public boolean validateXMLSignature(SignableXMLObject request, X509Credential cred,
                                        String alias) throws IdentityException {

        boolean isSignatureValid = false;

        if (request.getSignature() != null) {
            ClassLoader oldCL = Thread.currentThread().getContextClassLoader();
            ClassLoader opensamlCL = org.opensaml.xmlsec.signature.support.Signer.class.getClassLoader();

            try {
                Thread.currentThread().setContextClassLoader(opensamlCL);
                SignatureValidator.validate(request.getSignature(), cred);
                isSignatureValid = true;
            } catch (SignatureException e) {
                throw IdentityException.error("Signature Validation Failed for the SAML Assertion.", e);
            } finally {
                Thread.currentThread().setContextClassLoader(oldCL);
            }
        }
        return isSignatureValid;
    }

    @Override
    public SignableXMLObject setSignature(SignableXMLObject signableXMLObject, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentityException {

        Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(cred);
        signature.setSignatureAlgorithm(signatureAlgorithm);
        signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
        X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
        X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);

        String value;
        try {
            value = org.apache.xml.security.utils.Base64.encode(cred.getEntityCertificate().getEncoded());
        } catch (CertificateEncodingException e) {
            throw IdentityException.error("Error occurred while retrieving encoded cert", e);
        }

        cert.setValue(value);
        data.getX509Certificates().add(cert);
        keyInfo.getX509Datas().add(data);
        signature.setKeyInfo(keyInfo);

        signableXMLObject.setSignature(signature);
        ((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(digestAlgorithm);

        List<Signature> signatureList = new ArrayList<Signature>();
        signatureList.add(signature);

        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(signableXMLObject);

        try {
            marshaller.marshall(signableXMLObject);
        } catch (MarshallingException e) {
            throw IdentityException.error("Unable to marshall the request", e);
        }

        org.apache.xml.security.Init.init();
        
        ClassLoader oldCL = Thread.currentThread().getContextClassLoader();
        ClassLoader opensamlCL = org.opensaml.xmlsec.signature.support.Signer.class.getClassLoader();
        
        try {
            Thread.currentThread().setContextClassLoader(opensamlCL);
            Signer.signObjects(signatureList);
        } catch (SignatureException e) {
            throw IdentityException.error("Error occurred while signing request", e);
        } finally {
            Thread.currentThread().setContextClassLoader(oldCL);
        }

        return signableXMLObject;
    }

    /**
     * Builds SAML Elements
     *
     * @param objectQName
     * @return
     * @throws IdentityException
     */
    private XMLObject buildXMLObject(QName objectQName) throws IdentityException {
        XMLObjectBuilder builder =
                XMLObjectProviderRegistrySupport.getBuilderFactory()
                        .getBuilder(objectQName);
        if (builder == null) {
            throw IdentityException.error("Unable to retrieve builder for object QName " +
                    objectQName);
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(),
                objectQName.getPrefix());
    }
}
