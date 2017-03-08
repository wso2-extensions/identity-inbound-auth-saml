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

package org.wso2.carbon.identity.saml.builders.signature;

import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.common.base.exception.IdentityException;

import javax.xml.namespace.QName;

public class DefaultSSOSigner implements SSOSigner {


    public void init() throws IdentityException {
        //Overridden method, no need to implement the body
    }

    public SignableXMLObject setSignature(SignableXMLObject signableXMLObject, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentityException {

        SAML2AuthUtils.setSignature(signableXMLObject, signatureAlgorithm, digestAlgorithm, true, cred);
        return signableXMLObject;
    }

    public boolean validateXMLSignature(RequestAbstractType request, X509Credential cred,
                                        String alias) throws IdentityException {

        boolean isSignatureValid = false;

        if (request.getSignature() != null) {
            try {
                SignatureValidator validator = new SignatureValidator(cred);
                validator.validate(request.getSignature());
                isSignatureValid = true;
            } catch (ValidationException e) {
                throw IdentityException.error("Signature Validation Failed for the SAML Assertion : Signature is " +
                                              "invalid.", e);
            }
        }
        return isSignatureValid;
    }
}
