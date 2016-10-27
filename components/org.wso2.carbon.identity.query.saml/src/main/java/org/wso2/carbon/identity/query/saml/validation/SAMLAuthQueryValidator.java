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

package org.wso2.carbon.identity.query.saml.validation;

import org.opensaml.saml.saml2.core.AuthnQuery;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;

import java.util.List;

/**
 * This class is used to validate AuthnQuery request message
 *
 * @see org.opensaml.saml.saml2.core.AuthnQuery
 */
public class SAMLAuthQueryValidator extends SAMLSubjectQueryValidator {

    /**
     * This method is used to validate AuthnQuery message elements
     *
     * @param invalidItems List of invalid items tracked by validation process
     * @param request      AuthnQuery request message
     * @return Boolean true, if request message validated completely
     * @throws  IdentitySAML2QueryException If unable to validate AuthnQuery message
     */
    @Override
    public boolean validate(List<InvalidItemDTO> invalidItems, RequestAbstractType request)
            throws IdentitySAML2QueryException {
        boolean isSuperValid;
        boolean sessionIndexPresent = false;
        boolean authnContextClassRefPresent = false;
        isSuperValid = super.validate(invalidItems, request);
        if (isSuperValid) {
            AuthnQuery authnQuery = (AuthnQuery) request;
            if (authnQuery.getSessionIndex() != null && authnQuery.getSessionIndex().length() > 0) {
                sessionIndexPresent = true;
            }
            if (authnQuery.getRequestedAuthnContext().getAuthnContextClassRefs().size() > 0) {
                authnContextClassRefPresent = true;
            }
            if (sessionIndexPresent || authnContextClassRefPresent) {
                return true;
            } else {
                invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_AUTHN_QUERY,
                        SAMLQueryRequestConstants.ValidationMessage.VAL_AUTHN_QUERY_ERROR));
                return false;
            }
        } else {
            return isSuperValid;
        }
    }
}
