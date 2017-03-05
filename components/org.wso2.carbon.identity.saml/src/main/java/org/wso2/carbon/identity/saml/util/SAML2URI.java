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
package org.wso2.carbon.identity.saml.util;


public enum SAML2URI {

    NAMEID_FORMAT_ENTITY_IDENTIFIER("urn:oasis:names:tc:SAML:2.0:nameid-format:entity"),
    STATUS_CODE_VERSION_MISMATCH("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"),
    STATUS_CODE_REQUESTER("urn:oasis:names:tc:SAML:2.0:status:Requester");

    private String value;

    SAML2URI(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return this.value;
    }
}
