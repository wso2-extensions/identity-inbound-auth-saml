/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.sso.saml.validators;

import org.apache.commons.lang.StringUtils;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectImpl;
import org.opensaml.xml.XMLObject;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.sso.saml.SAMLTestRequestBuilder;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertEquals;

/**
 * Unit test cases for SPInitSSOAuthnRequestValidator.
 */
@PowerMockIgnore({"javax.net.*"})
@PrepareForTest({SAMLSSOUtil.class})
public class SPInitSSOAuthnRequestValidatorTest extends PowerMockTestCase {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @Test
    public void testValidateVersionError() throws Exception {

        AuthnRequest request = SAMLTestRequestBuilder.buildDefaultAuthnRequest();
        request.setVersion(SAMLVersion.VERSION_11);

        SAMLSSOReqValidationResponseDTO validationResp = executeValidate(request, true);
        assertFalse(validationResp.isValid(), "Authentication request validation should give invalid.");
        assertNotNull(validationResp.getResponse(), "Authentication request validation response should not be null.");
    }

    @Test
    public void testValidateNoIssuerError() throws Exception {

        AuthnRequest request = SAMLTestRequestBuilder.buildDefaultAuthnRequest();
        request.getIssuer().setValue(StringUtils.EMPTY);
        request.getIssuer().setSPProvidedID(StringUtils.EMPTY);

        SAMLSSOReqValidationResponseDTO validationResp = executeValidate(request, true);
        assertFalse(validationResp.isValid(), "Authentication request validation should give invalid.");
        assertNotNull(validationResp.getResponse(), "Authentication request validation response should not be null.");
    }

    @Test
    public void testValidateIssuerDoesNotExistError() throws Exception {

        SAMLSSOReqValidationResponseDTO validationResp = executeValidate(SAMLTestRequestBuilder.buildDefaultAuthnRequest(), false);
        assertFalse(validationResp.isValid(), "Authentication request validation should give invalid.");
        assertNotNull(validationResp.getResponse(), "Authentication request validation response should not be null.");
    }

    @Test
    public void testValidateIssuerFormatError() throws Exception {

        AuthnRequest request = SAMLTestRequestBuilder.buildDefaultAuthnRequest();
        request.getIssuer().setFormat("Invalid-Issuer-Format");

        SAMLSSOReqValidationResponseDTO validationResp = executeValidate(request, true);
        assertFalse(validationResp.isValid(), "Authentication request validation should give invalid.");
        assertNotNull(validationResp.getResponse(), "Authentication request validation response should not be null.");
    }

    @Test
    public void testValidateSubjectConformationsExistError() throws Exception {

        AuthnRequest request = SAMLTestRequestBuilder.buildDefaultAuthnRequest();

        SubjectImplExtend subjectImplExtend = spy(new SubjectImplExtend("namespaceURI", "elementLocalName",
                "namespacePrefix"));
        List<SubjectConfirmation> subjectConfirmations = new ArrayList<>();
        subjectConfirmations.add(new SubjectConfirmationBuilder().buildObject());
        doReturn(subjectConfirmations).when(subjectImplExtend).getSubjectConfirmations();

        request.setSubject(subjectImplExtend);

        SAMLSSOReqValidationResponseDTO validationResp = executeValidate(request, true);
        assertFalse(validationResp.isValid(), "Authentication request validation should give invalid.");
        assertNotNull(validationResp.getResponse(), "Authentication request validation response should not be null.");
    }

    private class SubjectImplExtend extends SubjectImpl {

        public SubjectImplExtend (String namespaceURI, String elementLocalName, String namespacePrefix) {
            super(namespaceURI, elementLocalName, namespacePrefix);
        }
    }

    @Test
    public void testValidateNoError() throws Exception {

        AuthnRequest request = SAMLTestRequestBuilder.buildDefaultAuthnRequest();
        SAMLSSOReqValidationResponseDTO validationResp = executeValidate(request, true);
        assertTrue(validationResp.isValid(), "Authentication request validation should give valid.");
        assertEquals(validationResp.getId(), request.getID(), "Authentication request validation response should have" +
                " the same ID as the request.");
        assertEquals(validationResp.getAssertionConsumerURL(), request.getAssertionConsumerServiceURL(),
                "Authentication request validation response should have the same ACS-URL as the request.");
        assertEquals(validationResp.getDestination(), request.getDestination(), "Authentication request validation " +
                "response should have the same destination as the request.");
        assertEquals(validationResp.isPassive(), (boolean) request.isPassive(), "Authentication request " +
                "validation response " +
                "should have the same isPassive as the request.");
        assertEquals(validationResp.isForceAuthn(), (boolean) request.isForceAuthn(), "Authentication request " +
                "validation response should have the same isForceAuthn as the request.");
    }

    @DataProvider(name = "testSplitAppendedTenantDomain")
    public static Object[][] issuerStrings() {
        return new Object[][]{{"travelocity@tenant.com", "tenant.com", "travelocity"},
                {"travelocity", null, "travelocity"}};
    }

    @Test(dataProvider = "testSplitAppendedTenantDomain")
    public void testSplitAppendedTenantDomain(String unsplittedIssuer, String tenantDomain, String actualIssuer) throws
            Exception {
        AuthnRequest request = SAMLTestRequestBuilder.buildDefaultAuthnRequest();
        SPInitSSOAuthnRequestValidator authnRequestValidator =
                (SPInitSSOAuthnRequestValidator) SAMLSSOUtil.getSPInitSSOAuthnRequestValidator(request);

        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.validateTenantDomain(anyString())).thenReturn(tenantDomain);

        String issuer = authnRequestValidator.splitAppendedTenantDomain(unsplittedIssuer);
        assertEquals(issuer, actualIssuer, "Should give the issuer without appended tenant domain.");
    }

    private SAMLSSOReqValidationResponseDTO executeValidate (AuthnRequest request, boolean shouldMakeSAMLIssuerExist)
            throws Exception {

        SAMLSSOUtil.doBootstrap();
        SSOAuthnRequestValidator authnRequestValidator =
                SAMLSSOUtil.getSPInitSSOAuthnRequestValidator(request);

        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.buildErrorResponse(anyString(), anyString(), anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.marshall(any(XMLObject.class))).thenCallRealMethod();
        when(SAMLSSOUtil.compressResponse(anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.getIssuer()).thenReturn(new IssuerBuilder().buildObject());
        when(SAMLSSOUtil.isSAMLIssuerExists(anyString(), anyString())).thenReturn(shouldMakeSAMLIssuerExist);

        return authnRequestValidator.validate();
    }
}
