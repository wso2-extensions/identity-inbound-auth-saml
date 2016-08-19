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

import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;

import java.util.List;

/**
 * SAMLQueryValidator interface has multiple implementations for validating different
 * request message types.Each message has different elements to validate and return assertions
 * according to the requirement.
 */
public interface SAMLQueryValidator {

    /**
     * This method is used to validate any type of request message
     *
     * @param request      any type of request message in <code>RequestAbstractType</code>
     * @param invalidItems List of invalid items
     * @return Boolean true, if request message contain no validation errors
     */
    boolean validate(List<InvalidItemDTO> invalidItems, RequestAbstractType request);


}
