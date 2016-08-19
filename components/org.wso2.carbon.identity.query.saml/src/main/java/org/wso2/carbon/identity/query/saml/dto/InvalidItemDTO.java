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

package org.wso2.carbon.identity.query.saml.dto;

/**
 * Class to hold validation issues for all request messages
 */
public class InvalidItemDTO {

    private String validationType;
    private String message;

    /**
     * Constructor
     *
     * @param validationType This is the type of validation error
     * @param message        This is the validation message
     */
    public InvalidItemDTO(String validationType, String message) {
        this.message = message;
        this.validationType = validationType;

    }

    /**
     * This method is used to get message
     *
     * @return String This returns message
     */
    public String getMessage() {

        return message;
    }


    /**
     * This method is used to get validation type
     *
     * @return String This returns validation type
     */
    public String getValidationType() {

        return validationType;
    }


}
