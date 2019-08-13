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
package org.wso2.carbon.identity.sso.saml.validators;

import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;

import java.security.cert.X509Certificate;

public interface SAML2HTTPRedirectSignatureValidator {

    public void init() throws IdentityException;

    /**
     *
     * @deprecated Use {@link #validateSignature(String, String, X509Certificate)}  instead.
     *
     * @param queryString
     * @param issuer
     * @param alias
     * @param domainName
     * @return
     * @throws org.opensaml.security.SecurityException
     * @throws IdentitySAML2SSOException
     */
    @Deprecated
    public boolean validateSignature(String queryString, String issuer, String alias,
                                     String domainName) throws org.opensaml.security.SecurityException, IdentitySAML2SSOException;

    /**
     * Validates the signature of the given SAML request against the given signature.
     *
     * @param queryString SAML request (passed an an HTTP query parameter)
     * @param issuer      Issuer of the SAML request
     * @param certificate Certificate for validating the signature
     * @return true if the signature is valid, false otherwise.
     * @throws org.opensaml.security.SecurityException if something goes wrong during signature validation.
     */
    boolean validateSignature(String queryString, String issuer, X509Certificate certificate)
            throws org.opensaml.security.SecurityException;
}
