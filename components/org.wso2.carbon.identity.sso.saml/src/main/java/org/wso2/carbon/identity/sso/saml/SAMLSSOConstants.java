/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sso.saml;

public class SAMLSSOConstants {

    public static final String NAME_ID_POLICY_ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";
    public static final String SUBJECT_CONFIRM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    public static final String NAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
    public static final String SAML_ASSERTION_URN = "urn:oasis:names:tc:SAML:2.0:assertion";
    public static final String NAMEID_FORMAT_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    public static final String PASSWORD_PROTECTED_TRANSPORT_CLASS =
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    public static final String SAML_PROTOCOL_URN = "urn:oasis:names:tc:SAML:2.0:protocol";
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";
    public static final String FEDERATED_IDP = "federated-idp-domain";
    public static final String ISSUER = "issuer";
    public static final String SAML_REQUEST = "SAMLRequest";
    public static final String AUTHN_REQUEST = "AuthnRequest";
    public static final String AUTH_MODE = "authMode";
    public static final String ASSRTN_CONSUMER_URL = "ACSUrl";
    public static final String REQ_ID = "id";
    public static final String SUBJECT = "subject";
    public static final String RP_SESSION_ID = "relyingPartySessionId";
    public static final String REQ_MSG_STR = "requestMessageString";
    public static final String DESTINATION = "destination";
    public static final String RELAY_STATE = "RelayState";
    public static final String AUTH_REQ_SAML_ASSRTN = "SAMLRequest";
    public static final String SAML_RESP = "SAMLResponse";
    public static final String SIG_ALG = "SigAlg";
    public static final String SIGNATURE = "Signature";
    public static final String HTTP_QUERY_STRING = "HttpQuerryString";
    public static final String TARGET_ASSRTN_CONSUMER_URL = "targetedAssrtnConsumerURL";
    public static final String kEEP_SESSION_ALIVE = "keepSessionAlive";
    public static final String LOGOUT_RESP = "logoutResponse";
    public static final String STATUS = "status";
    public static final String STATUS_MSG = "statusMsg";
    public static final String SSO_TOKEN_ID = "ssoTokenId";
    public static final String FE_SESSION_KEY = "authSession";
    public static final String AUTH_FAILURE = "authFailure";
    public static final String AUTH_FAILURE_MSG = "authFailureMsg";
    public static final String SAMLSSOServiceClient = "ssoServiceClient";
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String AUTHENTICATION_RESULT = "AuthenticationResult";
    public static final String LOGIN_PAGE = "customLoginPage";
    public static final String CLAIM_DIALECT_URL = "http://wso2.org/claims";
    public static final String SAML_ENDPOINT = "samlsso/carbon/";
    public static final String DEFAULT_LOGOUT_ENDPOINT = "/authenticationendpoint/samlsso_logout.do";
    public static final String SAMLSSO_URL = "/samlsso";
    public static final String NOTIFICATION_ENDPOINT = "/authenticationendpoint/samlsso_notification.do";
    public static final String SLO_SAML_SOAP_BINDING_ENABLED = "SSOService.SLOSAMLSOAPBindingEnabled";
    public static final String SAML2_AUTHENTICATION_REQUEST_VALIDITY_PERIOD_ENABLED = "SSOService.SAML2AuthenticationRequestValidityPeriodEnabled";
    public static final String SAML2_AUTHENTICATION_REQUEST_VALIDITY_PERIOD = "SSOService.SAML2AuthenticationRequestValidityPeriod";
    public static final String SAML_SP_CERTIFICATE_EXPIRY_VALIDATION_ENABLED = "SSOService.SAMLSPCertificateExpiryValidationEnable";
    public static final String SAML_IDP_INIT_LOGOUT_RESPONSE_SIGNING_ENABLED = "SSOService.SAMLIdpInitLogoutResponseSigningEnabled";
    public static final String SAML_ASSERTION_ENCRYPT_WITH_APP_CERT = "SSOService.SAMLAssertionEncyptWithAppCert";
    public static final String START_SOAP_BINDING = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
            "<SOAP-ENV:Body>";
    public static final String END_SOAP_BINDING = "</SOAP-ENV:Body>" +
            "</SOAP-ENV:Envelope>";
    public static final String SOAP_ACTION = "http://www.oasis-open.org/committees/security";
    public static final String XML_TAG_REGEX = "\\<\\?xml(.+?)\\?\\>";
    public static final String SAML_REQUEST_PARAM_KEY = "SAMLRequest";
    public static final String SOAP_ACTION_PARAM_KEY = "SOAPAction";
    public static final String COOKIE_PARAM_KEY = "Cookie";
    public static final String SESSION_ID_PARAM_KEY = "JSESSIONID=";
    public static final String ENCODING_FORMAT = "UTF-8";
    public static final String COM_PROTOCOL = "https";
    public static final String CRYPTO_PROTOCOL = "TLS";
    public static final String REQUESTED_ATTRIBUTES = "requested_attributes";

    public static final String AUTHN_CONTEXT_CLASS_REF = "AuthnContextClassRef";
    public static final String AUTHN_INSTANT = "AuthnInstant";
    public static final String SAML_SSO_ENCRYPTOR_CONFIG_PATH = "SSOService.SAMLSSOEncrypter";
    public static final String SAML2_HTTP_REDIRECT_SIGNATURE_VALIDATOR_CLASS_NAME = "SSOService.SAML2HTTPRedirectSignatureValidator";
    public static final String SAMLSSO_SIGNER_CLASS_NAME = "SSOService.SAMLSSOSigner";
    public static final String SAML_SSO_SP_REQUEST_VALIDATOR_CONFIG_PATH = "SSOService.SAMLSSOSPRequestValidator";
    public static final String INBOUND_AUTH_TYPE_SAML = "samlsso";
    public static final String SAML_SSO_TOKEN_ID_COOKIE = "samlssoTokenId";
    public static final String INBOUND_ISSUER_QUALIFIER = "spQualifier";
    public static final String TENANT_QUALIFIED_TOKEN_ID_COOKIE_SUFFIX = "-v2";
    public static final String COOKIE_ROOT_PATH = "/";
    public static final String IDP_SESSION_KEY = "isk";

    public static final String ATTR_NAME_AC_URL = "acUrl";
    public static final String ATTR_NAME_SP_NAME = "spName";
    public static final String ATTR_NAME_SAML_MESSAGE_TYPE = "samlMessageType";
    public static final String ATTR_NAME_SAML_MESSAGE = "samlMessage";
    public static final String ATTR_NAME_RELAY_STATE = "relayState";
    public static final String ATTR_NAME_AUTHENTICATED_IDPS = "authenticatedIdPs";

    // SAML2 Artifact Binding
    public static final byte[] SAML2_ARTIFACT_TYPE_CODE = { 0, 4 };
    public static final String SAML_ART = "SAMLart";
    public static final String SAML_ARTIFACT_RESOLVE_URL = "/samlartresolve";
    public static final String CONTENT_TYPE_PARAM_KEY = "Content-Type";
    public static final String PRAGMA_PARAM_KEY = "Pragma";
    public static final String CACHE_CONTROL_PARAM_KEY = "Cache-Control";
    public static final String CACHE_CONTROL_VALUE_NO_CACHE = "no-cache";

    public static final String IS_POST = "isPost";

    private SAMLSSOConstants() {
    }


    public enum QueryParameter {

        ACS("acs"),
        SLO("slo"),
        RETURN_TO("returnTo"),
        SP_ENTITY_ID("spEntityID"),
        SP_QUALIFIER("spQualifier");

        private final String parameterName;

        QueryParameter(String parameterName) {
            this.parameterName = parameterName;
        }

        @Override
        public String toString() {
            return parameterName;
        }
    }

    public static class FileBasedSPConfig {

        public static final String SERVICE_PROVIDERS = "ServiceProviders";
        public static final String SERVICE_PROVIDER = "ServiceProvider";
        public static final String ISSUER = "Issuer";
        public static final String ISSUER_QUALIFIER = "SpQualifier";
        public static final String NAMESPACE_PREFIX = "samlp";
        public static final String ASSERTION_CONSUMER_URL = "AssertionConsumerServiceURL";
        public static final String ACS_URLS = "AssertionConsumerServiceURLs";
        public static final String DEFAULT_ACS_URL = "DefaultAssertionConsumerServiceURL";
        public static final String CUSTOM_LOGIN_PAGE = "CustomLoginPage";
        public static final String SIGN_RESPONSE = "SignResponse";
        public static final String SIGN_ASSERTION = "SignAssertion";
        public static final String ENCRYPT_ASSERTION = "EncryptAssertion";
        public static final String SIG_VALIDATION = "ValidateSignatures";
        public static final String SINGLE_LOGOUT = "EnableSingleLogout";
        public static final String ATTRIBUTE_PROFILE = "EnableAttributeProfile";
        public static final String AUDIENCE_RESTRICTION = "EnableAudienceRestriction";
        public static final String RECIPIENT_VALIDATION = "EnableRecipients";
        public static final String IDP_INIT = "EnableIdPInitiatedSSO";
        public static final String USE_FULLY_QUALIFY_USER_NAME = "UseFullyQualifiedUsernameInNameID";
        public static final String ENABLE_IDP_INIT_SLO = "EnableIdPInitSLO";
        public static final String SSO_DEFAULT_SIGNING_ALGORITHM = "SAMLDefaultSigningAlgorithmURI";
        public static final String SSO_DEFAULT_DIGEST_ALGORITHM = "SAMLDefaultDigestAlgorithmURI";
        public static final String NAME_ID_FORMAT = "NameIDFormat";

        public static final String CERT_ALIAS = "CertAlias";
        public static final String LOGOUT_URL = "LogoutURL";
        public static final String SLO_RESPONSE_URL = "SLOResponseURL";
        public static final String SLO_REQUEST_URL = "SLORequestURL";
        public static final String CLAIMS = "Claims";
        public static final String CLAIM = "Claim";
        public static final String INCLUDE_ATTRIBUTE = "IncludeAttributeByDefault";
        public static final String AUDIENCE_LIST = "AudiencesList";
        public static final String AUDIENCE = "Audience";
        public static final String RECIPIENT_LIST = "RecipientList";
        public static final String RECIPIENT = "Recipient";
        public static final String CONSUMING_SERVICE_INDEX = "ConsumingServiceIndex";
        public static final String USE_AUTHENTICATED_USER_DOMAIN_CRYPTO = "SSOService.UseAuthenticatedUserDomainCrypto";
        public static final String RETURN_TO_URL_LIST = "ReturnToURLList";
        public static final String RETURN_TO_URL = "ReturnToURL";
        public static final String FRONT_CHANNEL_LOGOUT = "EnableFrontChannelLogout";
        public static final String FRONT_CHANNEL_LOGOUT_BINDING = "FrontChannelLogoutBinding";

        private FileBasedSPConfig() {
        }
    }

    public static class StatusCodes {
        public static final String SUCCESS_CODE = "urn:oasis:names:tc:SAML:2.0:status:Success";
        public static final String REQUESTOR_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        public static final String IDENTITY_PROVIDER_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Responder";
        public static final String VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
        public static final String AUTHN_FAILURE = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
        public static final String NO_PASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
        public static final String UNKNOWN_PRINCIPAL = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";

        private StatusCodes() {
        }
    }

    /**
     * Group the constants related to logs.
     */
    public static class LogConstants {

        public static final String CREATE_SAML_APPLICATION = "CREATE SAML APPLICATION";
        public static final String DELETE_SAML_APPLICATION = "DELETE SAML APPLICATION";
        public static final String SAML_INBOUND_SERVICE = "saml-inbound-service";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String PROCESS_SAML_LOGOUT = "process-saml-logout";
            public static final String VALIDATE_SAML_REQUEST = "validate-saml-request";
            public static final String PROCESS_SAML_REQUEST = "process-saml-request";
            public static final String HAND_OVER_TO_FRAMEWORK = "hand-over-to-framework";
        }

        /**
         * Define common and reusable Input keys for diagnostic logs.
         */
        public static class InputKeys {

            public static final String SAML_REQUEST = "saml request";
            public static final String ISSUER = "issuer";
            public static final String CONSUMER_URL = "consumer url";
            public static final String AUTH_MODE = "auth mode";
            public static final String ASSERTION_URL = "assertion url";
            public static final String QUERY_STRING = "query string";
        }
    }

    public static class SingleLogoutCodes {
        public static final String LOGOUT_USER = "urn:oasis:names:tc:SAML:2.0:logout:user";
        public static final String LOGOUT_ADMIN = "urn:oasis:names:tc:SAML:2.0:logout:admin";

        private SingleLogoutCodes() {
        }
    }

    public static class AuthnModes {
        public static final String USERNAME_PASSWORD = "usernamePasswordBasedAuthn";
        public static final String OPENID = "openIDBasedAuthn";

        private AuthnModes() {
        }
    }

    public static class Attribute {
        public static final String ISSUER_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

        private Attribute() {
        }
    }

    public static class Notification {
        public static final String EXCEPTION_STATUS = "Error when processing the authentication request!";
        public static final String EXCEPTION_MESSAGE = "Please try login again.";
        public static final String NORELAY_STATUS = "RealyState is not present in the request!";
        public static final String NORELAY_MESSAGE = "This request will not be processed further.";
        public static final String INVALID_MESSAGE_STATUS = "Not a valid SAML 2.0 Request Message!";
        public static final String INVALID_MESSAGE_MESSAGE = "The message was not recognized by the SAML 2.0 SSO Provider. Please check the logs for more details";
        public static final String INVALID_SESSION = "Server can not find any established sessions";
        public static final String SP_ENTITY_ID_NOT_AVAILABLE = "spEntityID must be mentioned in the IdP initiated "
                + "logout request";
        public static final String INVALID_SP_ENTITY_ID = "Invalid spEntityID '%s' value in the IdP initiated logout "
                + "request";
        public static final String IDP_SLO_NOT_ENABLED = "IdP initiated single logout is not enabled for the service"
                + " provider '%s'";
        public static final String IDP_SLO_VALIDATE_ERROR = "Error occurred while validating the IdP Initiated SLO " +
                "request";
        public static final String NO_SP_ENTITY_PARAM = "spEntity parameter must present if returnTo parameter " +
                "used in the request ";
        public static final String INVALID_RETURN_TO_URL = "Invalid 'returnTo' URL in the request";
        public static final String ERROR_RETRIEVE_TENANT_ID = "Error occurred while retrieving tenant id from tenant " +
                "domain";
        public static final String INVALID_TENANT_DOMAIN = "Service provider tenant domain '%s' is invalid";
        public static final String ERROR_RETRIEVE_SP_CONFIG = "Error occurred while loading Service Provider " +
                "configurations";
        public static final String EXCEPTION_STATUS_ARTIFACT_RESOLVE = "Error while resolving SAML artifact";

        private Notification() {
        }
    }

}

