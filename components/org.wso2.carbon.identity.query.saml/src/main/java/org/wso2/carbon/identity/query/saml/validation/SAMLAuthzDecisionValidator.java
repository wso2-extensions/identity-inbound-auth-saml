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

import org.opensaml.saml.saml2.core.Action;
import org.opensaml.saml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;

import java.util.List;

/**
 * This class is used to validate AuthzDecisionQuery message
 *
 * @see org.opensaml.saml.saml2.core.AuthzDecisionQuery
 */
public class SAMLAuthzDecisionValidator extends SAMLSubjectQueryValidator {

    /**
     * This method is used to validate AuthzDecisionQuery message
     *
     * @param invalidItems List of invalid items tracked by validation process
     * @param request      AuthzDecisionQuery request message
     * @return Boolean true, if request message is valid
     */
    @Override
    public boolean validate(List<InvalidItemDTO> invalidItems, RequestAbstractType request) {
        boolean isSuperValidated;
        isSuperValidated = super.validate(invalidItems, request);
        if (isSuperValidated) {
            List<Action> actions = ((AuthzDecisionQuery) request).getActions();
            String resource = ((AuthzDecisionQuery) request).getResource();
            return (actions.size() > 0) && resource.length() > 0;
        } else {
            return false;
        }
    }
}
