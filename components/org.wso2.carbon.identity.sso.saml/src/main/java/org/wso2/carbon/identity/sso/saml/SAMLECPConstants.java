/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

/**
 * This class defines the SAML ECP Constants.
 */
public class SAMLECPConstants {

    public static final String SAMLECP_URL = "/samlecp";
    public static final String IS_ECP_REQUEST  = "isECPRequest";
    public static final String AUTHORIZATION_HEADER = "Authorization";

    public static final boolean SAML_ECP_ENABLED = false; // Flag to internally disable SAML ECP feature


    /**
     * This class defines the SOAP Fault Codes for SOAP Faults.
     */
    public static class FaultCodes {

        public static final String SOAP_FAULT_CODE_CLIENT = "Client";
        public static final String SOAP_FAULT_CODE_SERVER = "Server";
    }

    /**
     * This class defines the SOAP Header Elements for SOAP Responses.
     */
    public static class SOAPHeaderElements {

        public static final String SOAP_HEADER_ELEMENT_ACS_URL = "AssertionConsumerServiceURL";
        public static final String SOAP_HEADER_ELEMENT_ACTOR = "http://schemas.xmlsoap.org/soap/actor/next";
    }

    /**
     * This class defines the ECP Header Elements for SOAP Responses.
     */
    public static class SOAPECPHeaderElements {
        public static final String SOAP_ECP_HEADER_LOCAL_NAME = "Response";
        public static final String SOAP_ECP_HEADER_PREFIX = "ecp";
        public static final String SOAP_ECP_HEADER_URI = "urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp";
    }

    public static class SOAPNamespaceURI {
        public static final String SOAP_NAMESPACE_URI = "http://schemas.xmlsoap.org/soap/envelope/";
    }
}
