/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml.extension;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.StatusResponseType;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;

/**
 * This is used to process and validate the SAML extensions.
 */
public interface SAMLExtensionProcessor {

    /**
     * Check whether the SAML request can be handled by this extension processor.
     *
     * @param request SAML request
     * @return true if the request can be handled
     * @throws IdentitySAML2SSOException
     */
    public boolean canHandle(RequestAbstractType request) throws IdentitySAML2SSOException;

    /**
     * Check whether the SAML response can be handled by this extension processor.
     *
     * @param response   SAML response
     * @param assertion  SAML assertion
     * @param authReqDTO Authentication request data object
     * @return true if the request can be handled
     * @throws IdentitySAML2SSOException
     */
    public boolean canHandle(StatusResponseType response, Assertion assertion, SAMLSSOAuthnReqDTO authReqDTO)
            throws IdentitySAML2SSOException;

    /**
     * Process the SAML extensions in a request.
     *
     * @param request SAML request
     * @param validationResp Authentication response data object
     * @throws IdentitySAML2SSOException
     */
    public void processSAMLExtensions(RequestAbstractType request, SAMLSSOReqValidationResponseDTO validationResp)
            throws IdentitySAML2SSOException;

    /**
     * Process the SAML extensions in a response or process against the SAML request with extensions.
     *
     * @param response SAML response
     * @param assertion SAML assertion
     * @param authReqDTO Authentication request data object
     * @throws IdentitySAML2SSOException
     */
    public void processSAMLExtensions(StatusResponseType response, Assertion assertion, SAMLSSOAuthnReqDTO authReqDTO)
            throws IdentitySAML2SSOException;
}
