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
        public static final String INTERNAL_SERVER_ERROR = "Internal Server Error";
        public static final String VAL_MESSAGE_TYPE = "Validation Message Type";
        public static final String VAL_VERSION = "Validating the Version";
        public static final String VAL_ISSUER = "Checking for Issuer";
        public static final String VAL_SIGNATURE = "Validating Signature";
        public static final String NO_ASSERTIONS = "No Assertions Matched";
        public static final String VAL_ASSERTION_ID = "Invalid Assertion ID";
        public static final String VAL_SUBJECT = "Invalid Subject";
        public static final String VAL_ACTIONS = "No Actions";
        public static final String VAL_RESOURCE = "No Resource";
        public static final String VAL_AUTHN_QUERY = "No sessionIndex or AuthnContextClassRefs";
        public static final String STRING_TO_OMELEMENT = "String convert to OMElement";
        public static final String NULL_OMELEMENT = "OMElement is null";
        public static final String VAL_VALIDATION_ERROR = "Validation error";
        public static final String VAL_PROFILE_ENABLED = "Checking Assertion Query/Request profile enabled";
    }

    /**
     * Standard class to represent validation messages
     */
    public static class ValidationMessage {

        public static final String VALIDATION_ERROR = "Request message contain validation errors";
        public static final String VAL_MESSAGE_BODY_ERROR = "Message Body is Empty";
        public static final String VAL_INTERNAL_SERVER_ERROR = "Internal Server Error Occurred";
        public static final String VAL_MESSAGE_TYPE_ERROR = "Invalid Standard Request Message Type";
        public static final String VAL_VERSION_ERROR = "Invalid SAML version, expected version is 2.0";
        public static final String VAL_ISSUER_ERROR = "Issuer is Not Validated";
        public static final String VAL_SIGNATURE_ERROR = "Signature Validation for Request Failed";
        public static final String NO_ASSERTIONS_ERROR = "No Assertions match with request";
        public static final String VAL_ASSERTION_ID_ERROR = "AssertionID request contain Invalid Assertion ID";
        public static final String VAL_SUBJECT_ERROR = "Request subject is invalid";
        public static final String VAL_ACTIONS_ERROR = "AuthzDecision request contain no actions";
        public static final String VAL_RESOURCE_ERROR = "AuthzDecision request do not present resource";
        public static final String VAL_AUTHN_QUERY_ERROR = "Request message type does present any sessionindex or" +
                " authncontextclassref";
        public static final String STRING_TO_OMELEMENT_ERROR = "Unable to convert String to OMElement";
        public static final String NULL_OMELEMENT_ERROR = "OMElement is null after converting from String";
        public static final String VAL_PROFILE_ENABLED_ERROR = "Assertion Query/Request profile not enabled";

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
        public static final String SOAP_RESPONSE_CREATION_FAILED = "Internal Error on Creating SOAP Response ";
        public static final String MARSHAL_ERROR = "Unable to Marshal Response ";
    }

    /**
     * Standard class for generic constants
     */
    public static class GenericConstants {
        public static final String UTF8_ENC = "UTF-8";
        public static final String ISSUER_FORMAT =
                "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
        public static final String ATTRIBUTE_HANDLER = "SAMLQuery.AttributeHandlers";
        public static final String ASSERTION_HANDLER = "SAMLQuery.AssertionFinders";
        public static final String HANDLER_PROPERY_DELIMETER = ",";

    }
}
