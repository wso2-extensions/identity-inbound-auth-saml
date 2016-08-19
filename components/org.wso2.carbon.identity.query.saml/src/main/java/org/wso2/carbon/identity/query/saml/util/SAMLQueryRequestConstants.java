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

package org.wso2.carbon.identity.query.saml.util;

/**
 * Class to represent constant values
 */
public class SAMLQueryRequestConstants {

    /**
     * Class for standard validation types which represent individual validations
     */
    public static class ValidationType {


        public static final String VAL_MESSAGE_BODY = "Validation Message Body";
        public static final String VAL_UNMARSHAL = "UnMarshalling the Request";
        public static final String VAL_MESSAGE_TYPE = "Validation Message Type";
        public static final String VAL_VERSION = "Validating the Version";
        public static final String VAL_ISSUER = "Checking for Issuer";
        public static final String VAL_SIGNATURE = "Validating Signature";
        public static final String NO_ASSERTIONS = "No Assertions Found";
    }

    /**
     * Standard class to represent validation messages
     */
    public static class ValidationMessage {

        public static final String EXIT_WITH_ERROR = "Validation service error exit.";
        public static final String ERROR_LOADING_SP_CONF = "Error while reading Service Provider configurations.";
        public static final String VAL_MESSAGE_BODY_ERROR = "Message Body is Empty";
        public static final String VAL_UNMARSHAL_FAIL = " Unable to UnMarshall the request";
        public static final String VAL_MESSAGE_TYPE_ERROR = "Invalid Standard Request Message Type";
        public static final String VAL_VERSION_ERROR = "Invalid SAML version, expected version is 2.0";
        public static final String VAL_ISSUER_ERROR = "Issuer is Not Validated";
        public static final String VAL_SIGNATURE_ERROR = "Signature Validation for Request Failed";
        public static final String NO_ASSERTIONS_ERROR = "No Assertions Found on Server";

    }

    /**
     * Standard class to represent server status messages
     */
    public static class ServiceMessages {
        public static final String SERVICE_STARTED = "Assertion Query/Request Profile Started";
        public static final String SIGNATURE_VALIDATION_FAILED = "Internal Error in Signature Validation";
        public static final String ISSUER_VALIDATION_FAILED = "Internal Error in Issuer Validation";
        public static final String NULL_ISSUER = "Issuer Collected With Null Value";
        public static final String NO_ISSUER_PRESENTED = "Issuer Element Not Presented";
        public static final String SUCCESS_ISSUER = "Issuer Collected Successfully With : ";
        public static final String SERVER_ERROR_PROCESSING_ISSUER_SIG_VERSION = "Internal Error in Processing Issuer, Signature and Version";
        public static final String NON_COMPAT_SAML_VERSION = "Request contain non SAML 2.0";
        public static final String COMPLETE_VALIDATION = "Request Message Validated";
        public static final String SOAP_RESPONSE_CREATED = "SOAP Response Created";
        public static final String SOAP_RESPONSE_CREATION_FAILED = "Internal Error in Creating SOAP Response ";
        public static final String MARSHAL_ERROR = "Unable to Marshal Response ";
    }

    /**
     * Standard class for generic constants
     */
    public static class GenericConstants {
        public static final String UTF8_ENC = "UTF-8";
        public static final String ISSUER_FORMAT =
                "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

    }
}
