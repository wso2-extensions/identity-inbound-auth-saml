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
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.internal.SAMLQueryServiceComponent;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;

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
     * @throws IdentitySAML2QueryException If unable to validate SubjectQuery
     */
    @Override
    public boolean validate(List<InvalidItemDTO> invalidItems, RequestAbstractType request)
            throws IdentitySAML2QueryException {
        boolean isSuperValidated = super.validate(invalidItems, request);
        if (isSuperValidated) {
            boolean isSubjectValid;
            isSubjectValid = this.validateSubject((SubjectQueryImpl) request);
            if (!isSubjectValid) {
                invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_SUBJECT,
                        SAMLQueryRequestConstants.ValidationMessage.VAL_SUBJECT_ERROR));
            }
            return isSubjectValid;
        } else {
            invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_SUBJECT,
                    SAMLQueryRequestConstants.ValidationMessage.VAL_SUBJECT_ERROR));
            return false;
        }

    }

    /**
     * This method is used to validate subject of the request message
     *
     * @param subjectQuery SubjectQuery request message
     * @return Boolean true, if request subject is valid
     */
    protected boolean validateSubject(SubjectQueryImpl subjectQuery) throws IdentitySAML2QueryException {
        Subject subject = subjectQuery.getSubject();
        boolean isValidsubject = false;
        try {
            if (subject != null && subject.getNameID() != null &&
                    subject.getNameID().getFormat() != null && super.getSsoIdpConfig().getNameIDFormat() != null &&
                    subject.getNameID().getFormat().equals(super.getSsoIdpConfig().getNameIDFormat())) {
                UserStoreManager userStoreManager = SAMLQueryServiceComponent.getRealmservice().
                        getTenantUserRealm(CarbonContext.getThreadLocalCarbonContext().getTenantId()).
                        getUserStoreManager();
                String user = subject.getNameID().getValue();
                if (userStoreManager.isExistingUser(user)) {
                    log.debug("Request with id:" + subjectQuery.getID() + " contain valid subject");
                    isValidsubject = true;
                } else {
                    log.debug("Request message subject :" + user + " is invalid");
                }

            } else {
                log.debug("Request with id:" + subjectQuery.getID() + " contain in-valid subject");
                return isValidsubject;
            }
        }  catch (UserStoreException e) {
            log.error("Unable to collect requested subject from user store",e);
        }
        return isValidsubject;
    }
}
