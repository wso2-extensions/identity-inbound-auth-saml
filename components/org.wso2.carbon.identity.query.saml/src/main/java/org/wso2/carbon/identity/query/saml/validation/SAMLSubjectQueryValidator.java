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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.impl.SubjectQueryImpl;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;

import java.util.List;

/**
 * This class is used to validate <code>SubjectQuery</code> as the parent message
 * of AttributeQuery,AuthnQuery,AuthzDecisionQuery
 *
 * @see org.opensaml.saml.saml2.core.SubjectQuery
 */
public class SAMLSubjectQueryValidator extends AbstractSAMLQueryValidator {

    private final static Log log = LogFactory.getLog(SAMLSubjectQueryValidator.class);

    /**
     * This method is used to validate SubjectQuery super class
     *
     * @param invalidItems List of invalid items tracked by validation process
     * @param request      Any type of assertion request
     * @return Boolean true, if request message contain no validation errors
     */
    @Override
    public boolean validate(List<InvalidItemDTO> invalidItems, RequestAbstractType request) {
        boolean isSuperValidated = super.validate(invalidItems, request);
        if (!isSuperValidated) {

            return false;
        }
        boolean isSubjectValid;
        isSubjectValid = this.validateSubject((SubjectQueryImpl) request);
        return isSubjectValid;
    }

    /**
     * This method is used to validate subject of the request message
     *
     * @param subjectQuery SubjectQuery request message
     * @return Boolean true, if request subject is valid
     */
    protected boolean validateSubject(SubjectQueryImpl subjectQuery) {
        Subject subject = subjectQuery.getSubject();
        boolean isValidsubject = false;

        if (subject != null && subject.getNameID() != null &&
                subject.getNameID().getFormat() != null && super.getSsoIdpConfig().getNameIDFormat() != null &&
                subject.getNameID().getFormat().equals(super.getSsoIdpConfig().getNameIDFormat())) {
            log.debug("Request subject is valid");
            isValidsubject = true;
        }
        return isValidsubject;
    }
}
