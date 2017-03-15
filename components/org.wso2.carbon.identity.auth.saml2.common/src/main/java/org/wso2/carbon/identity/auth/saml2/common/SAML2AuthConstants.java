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

    /**
     * Standard constants
     */
    public static final String SAML_REQUEST = "SAMLRequest";
    public static final String SAML_RESPONSE = "SAMLResponse";
    public static final String RELAY_STATE = "RelayState";
    public static final String SIG_ALG = "SigAlg";
    public static final String SIGNATURE = "Signature";
    public static final String SP_ENTITY_ID = "spEntityId";
    public static final String ACS = "acs";

    /**
     * Non-standard constants
     */
    public static final String SAML_CONTEXT = "SAML2SSOContext";
    public static final String ASSRTN_CONSUMER_URL = "ACSUrl";

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
        }

    }

    /**
     * XML.
     */
    public static class XML {

        /**
         * Signature algorithms.
         */
        public static class SignatureAlgorithm {
            public static final String DSA_SHA1 = "DSA with SHA1";
            public static final String ECDSA_SHA1 = "ECDSA with SHA1";
            public static final String ECDSA_SHA256 = "ECDSA with SHA256";
            public static final String ECDSA_SHA384 = "ECDSA with SHA384";
            public static final String ECDSA_SHA512 = "ECDSA with SHA512";
            public static final String RSA_MD5 = "RSA with MD5";
            public static final String RSA_RIPEMD160 = "RSA with RIPEMD160";
            public static final String RSA_SHA1 = "RSA with SHA1";
            public static final String RSA_SHA256 = "RSA with SHA256";
            public static final String RSA_SHA384 = "RSA with SHA384";
            public static final String RSA_SHA512 = "RSA with SHA512";
        }

        /**
         * Signature algorithm URIs.
         */
        public static class SignatureAlgorithmURI {
            public static final String DSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
            public static final String ECDSA_SHA1 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
            public static final String ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
            public static final String ECDSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
            public static final String ECDSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
            public static final String RSA_MD5 = "http://www.w3.org/2001/04/xmldsig-more#rsa-md5";
            public static final String RSA_RIPEMD160 = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";
            public static final String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
            public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            public static final String RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
            public static final String RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
        }

        /**
         * Digest algorithm.
         */
        public static class DigestAlgorithm {
            public static final String MD5 = "MD5";
            public static final String RIPEMD160 = "RIPEMD160";
            public static final String SHA1 = "SHA1";
            public static final String SHA256 = "SHA256";
            public static final String SHA384 = "SHA384";
            public static final String SHA512 = "SHA512";
        }

        /**
         * Digest algorithm URIs.
         */
        public static class DigestAlgorithmURI {
            public static final String MD5 = "http://www.w3.org/2001/04/xmldsig-more#md5";
            public static final String RIPEMD160 = "http://www.w3.org/2001/04/xmlenc#ripemd160";
            public static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
            public static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
            public static final String SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384";
            public static final String SHA512 = "http://www.w3.org/2001/04/xmlenc#sha512";
        }


        public static class CanonicalizationAlgorithm {
            public static final String ALGO_ID_C14N_OMIT_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
            public static final String ALGO_ID_C14N_WITH_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
            public static final String ALGO_ID_C14N_EXCL_OMIT_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#";
            public static final String ALGO_ID_C14N_EXCL_WITH_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
            public static final String ALGO_ID_C14N11_OMIT_COMMENTS = "http://www.w3.org/2006/12/xml-c14n11";
            public static final String ALGO_ID_C14N11_WITH_COMMENTS = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
            public static final String ALGO_ID_C14N_PHYSICAL = "http://santuario.apache.org/c14n/physical";
        }
    }
}
