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

package org.wso2.carbon.identity.auth.saml2.common;

/**
 * SAML2 Constants used for inbound and outbound authentication.
 */
public class SAML2AuthConstants {

    public static final String SAML_REQUEST = "SAMLRequest";
    public static final String SAML_RESPONSE = "SAMLResponse";
    public static final String RELAY_STATE = "RelayState";

    /**
     * Constants used for inbound and outbound configurations.
     */
    public static class Config {

        /**
         * Constants used for inbound and outbound configuration keys.
         */
        public static class Name {
            public static final String SP_ENTITY_ID = "SPEntityId";
            public static final String IDP_ENTITY_ID = "IdPEntityId";
            public static final String ATTRIBUTE_CONSUMING_SERVICE_INDEX = "AttributeConsumingServiceIndex";
            public static final String INCLUDE_NAME_ID_POLICY = "IncludeNameIdPolicy";
            public static final String INCLUDE_AUTHN_CONTEXT = "IncludeAuthnContext";
            public static final String AUTHN_CONTEXT_CLASS_REF = "AuthnContextClassRef";
            public static final String AUTHN_CONTEXT_COMPARISON = "AuthnContextComparison";
            public static final String REQUEST_BINDING = "RequestBinding";
            public static final String SAML2_SSO_URL = "SAML2SSOUrl";
            public static final String ACS_URL = "ACSUrl";
            public static final String FORCE = "Force";
            public static final String PASSIVE = "Passive";
            public static final String AUTHN_REQUEST_SIGNED = "AuthnRequestSigned";
            public static final String AUTHN_RESPONSE_SIGNED = "AuthnResponseSigned";
            public static final String AUTHN_RESPONSE_ENCRYPTED = "AuthnResponseEncrypted";
            public static final String SIGNATURE_ALGO = "SignatureAlgo";
            public static final String DIGEST_ALGO = "DigestAlgo";
        }

        /**
         * Constants used for inbound and outbound configuration values.
         */
        public static class Value {
            public static final String AS_REQUEST = "AS_REQUEST";
            public static final String POST = "POST";
            public static final String REDIRECT = "REDIRECT";
            public static final String GET = "GET";
            public static final String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
            public static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

        }

    }
}
