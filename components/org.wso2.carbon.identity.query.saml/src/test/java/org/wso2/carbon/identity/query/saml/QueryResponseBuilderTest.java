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

import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.impl.AssertionImpl;
import org.opensaml.saml.saml2.core.impl.IssuerImpl;
import org.opensaml.saml.saml2.core.impl.ResponseImpl;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.util.OpenSAML3Util;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Test Class for the QueryResponseBuilder.
 */
@PrepareForTest({OpenSAML3Util.class, QueryResponseBuilder.class})
public class QueryResponseBuilderTest extends PowerMockTestCase {

    @Test
    public void testBuildforSuccess() throws Exception {

        DummyAssertion dummyAssertion = new DummyAssertion();
        List<Assertion> assertions = new ArrayList<>();
        SAMLSSOServiceProviderDO ssoIdpConfigs = new SAMLSSOServiceProviderDO();
        Response response = new DummyResponse();
        assertions.add(dummyAssertion);
        DummyIssuer issuer = new DummyIssuer();

        mockStatic(OpenSAML3Util.class);
        when(OpenSAML3Util.getIssuer(anyString())).thenReturn(issuer);
        when(OpenSAML3Util.setSignature(any(Response.class), anyString(),
                anyString(), any(SignKeyDataHolder.class))).thenReturn(response);

        SignKeyDataHolder testSign = Mockito.mock(SignKeyDataHolder.class);
        whenNew(SignKeyDataHolder.class).withAnyArguments().thenReturn(testSign);
        assertTrue(QueryResponseBuilder.build(assertions, ssoIdpConfigs, "test").getAssertions() != null);

    }

    @Test
    public void testBuildforError() throws IdentitySAML2QueryException {

        DummyIssuer issuer = new DummyIssuer();
        DummyIssuer issuer2 = new DummyIssuer();
        List<InvalidItemDTO> invalidItems = new ArrayList<>();
        mockStatic(OpenSAML3Util.class);
        when(OpenSAML3Util.getIssuer(anyString())).thenReturn(issuer);
        Response testresponse1 = QueryResponseBuilder.build(invalidItems);
        when(OpenSAML3Util.getIssuer(anyString())).thenReturn(issuer2);
        invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_SUBJECT,
                SAMLQueryRequestConstants.ValidationMessage.VAL_SUBJECT_ERROR));
        Response testresponse2 = QueryResponseBuilder.build(invalidItems);

        assertEquals(testresponse1.getStatus().getStatusCode().getValue(), null);
        assertEquals(testresponse1.getStatus().getStatusMessage().getMessage(), null);
        assertEquals(testresponse2.getStatus().getStatusMessage().getMessage(), "Request subject is invalid");
        assertEquals(testresponse2.getStatus().getStatusCode().getValue(), "urn:oasis:names:tc:SAML:2.0:status:Requester");
    }

    @Test
    public void testBuildStatus() {

        Status dummyStatus1 = QueryResponseBuilder.buildStatus("teststatus1", "testmsg");
        Status dummyStatus2 = QueryResponseBuilder.buildStatus("teststatus2", null);
        assertEquals(dummyStatus1.getStatusMessage().getMessage(), "testmsg");
        assertEquals(dummyStatus2.getStatusMessage(), null);
        assertEquals(dummyStatus1.getStatusCode().getValue(), "teststatus1");
        assertEquals(dummyStatus2.getStatusCode().getValue(), "teststatus2");
    }

    @DataProvider(name = "provideValidationType")
    public Object[][] createValidationType() {

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

    @Test(dataProvider = "provideValidationType")
    public void testFilterStatusCode(String status, String response)  {

        assertEquals(QueryResponseBuilder.filterStatusCode(status), response);
    }

    class DummyIssuer extends IssuerImpl {

        protected DummyIssuer() {
            super("testNSU", "testELN", "testNSP");
        }

    }

    class DummyAssertion extends AssertionImpl {

        protected DummyAssertion() {
            super("testNSU", "testELN", "testNSP");
        }
    }

    class DummyResponse extends ResponseImpl {

        protected DummyResponse() {
            super("testNSU", "testELN", "testNSP");
        }
    }

}
