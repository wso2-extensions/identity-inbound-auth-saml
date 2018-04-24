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

package org.wso2.carbon.identity.sso.saml.extension.eidas.util;

/**
 * Constants for the eIDAS extension processing.
 */
public class EidasConstants {

    public static final String EIDAS_NS = "http://eidas.europa.eu/saml-extensions";
    public static final String EIDAS_PREFIX = "eidas";
    public static final String EIDAS_REQUEST = "request_type";
    public static final String EIDAS_ATTRIBUTE_NAME_FORMAT = "NameFormat";
    public static final String EIDAS_ATTRIBUTE_NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    public static final String EIDAS_ATTRIBUTE_NAME = "Name";
    public static final String EIDAS_ATTRIBUTE_REQUIRED = "isRequired";
    public static final String EIDAS_SP_TYPE_PUBLIC = "public";
    public static final String EIDAS_SP_TYPE_PRIVATE = "private";

    private EidasConstants() {
    }

}
