/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.query.saml;

import org.opensaml.saml.saml2.core.impl.StatusImpl;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Test Class for the QueryResponseBuilder
 */
public class QueryResponseBuilderTest {

    @DataProvider(name = "provideStatusCode")
    public Object[][] createSubject() {

        String VAL_MESSAGE_BODY = "Validation Message Body";
        String INTERNAL_SERVER_ERROR = "Internal Server Error";
        String VAL_MESSAGE_TYPE = "Validation Message Type";
        String VAL_VERSION = "Validating the Version";
        String VAL_ISSUER = "Checking for Issuer";
        String VAL_SIGNATURE = "Validating Signature";
        String NO_ASSERTIONS = "No Assertions Matched";
        String VAL_ASSERTION_ID = "Invalid Assertion ID";
        String VAL_SUBJECT = "Invalid Subject";
        String VAL_ACTIONS = "No Actions";
        String VAL_RESOURCE = "No Resource";
        String VAL_AUTHN_QUERY = "No sessionIndex or AuthnContextClassRefs";
        String STRING_TO_OMELEMENT = "String convert to OMElement";
        String NULL_OMELEMENT = "OMElement is null";
        String VAL_VALIDATION_ERROR = "Validation error";
        String VAL_PROFILE_ENABLED = "Checking Assertion Query/Request profile enabled";

        String SUCCESS_CODE = "urn:oasis:names:tc:SAML:2.0:status:Success";
        String REQUESTOR_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        String IDENTITY_PROVIDER_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Responder";
        String VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
        String AUTHN_FAILURE = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
        String NO_PASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
        String UNKNOWN_PRINCIPAL = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";
        String NO_AUTHN_CONTEXT = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";
        return new Object[][]{
                {VAL_VERSION, VERSION_MISMATCH},
                {VAL_ISSUER, UNKNOWN_PRINCIPAL},
                {VAL_SIGNATURE, REQUESTOR_ERROR},
                {VAL_MESSAGE_TYPE, REQUESTOR_ERROR},
                {VAL_MESSAGE_BODY, REQUESTOR_ERROR},
                {NO_ASSERTIONS, NO_AUTHN_CONTEXT},
                {VAL_ASSERTION_ID, REQUESTOR_ERROR},
                {VAL_SUBJECT, REQUESTOR_ERROR},
                {VAL_ACTIONS, REQUESTOR_ERROR},
                {VAL_RESOURCE, REQUESTOR_ERROR},
                {VAL_AUTHN_QUERY, REQUESTOR_ERROR},
                {STRING_TO_OMELEMENT, IDENTITY_PROVIDER_ERROR},
                {NULL_OMELEMENT, IDENTITY_PROVIDER_ERROR},
                {VAL_VALIDATION_ERROR, REQUESTOR_ERROR},
                {INTERNAL_SERVER_ERROR, IDENTITY_PROVIDER_ERROR},
                {VAL_PROFILE_ENABLED, IDENTITY_PROVIDER_ERROR},
        };
    }

    @Test(dataProvider = "provideStatusCode")
    public void testFilterStatusCode(String status, String response) throws Exception {

        assertEquals(QueryResponseBuilder.filterStatusCode(status), response);
    }

}