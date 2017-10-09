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
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.*;
import static org.testng.Assert.*;

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

        AuthnRequest request = getAuthnRequest();
        request.setVersion(SAMLVersion.VERSION_11);

        SAMLSSOReqValidationResponseDTO validationResp = executeValidate(request, true);
        assertFalse(validationResp.isValid(), "Authentication request validation should give invalid.");
        assertNotNull(validationResp.getResponse(), "Authentication request validation response should not be null.");
    }

    @Test
    public void testValidateNoIssuerError() throws Exception {

        AuthnRequest request = getAuthnRequest();
        request.getIssuer().setValue(StringUtils.EMPTY);
        request.getIssuer().setSPProvidedID(StringUtils.EMPTY);

        SAMLSSOReqValidationResponseDTO validationResp = executeValidate(request, true);
        assertFalse(validationResp.isValid(), "Authentication request validation should give invalid.");
        assertNotNull(validationResp.getResponse(), "Authentication request validation response should not be null.");
    }

    @Test
    public void testValidateIssuerDoesNotExistError() throws Exception {

        SAMLSSOReqValidationResponseDTO validationResp = executeValidate(getAuthnRequest(), false);
        assertFalse(validationResp.isValid(), "Authentication request validation should give invalid.");
        assertNotNull(validationResp.getResponse(), "Authentication request validation response should not be null.");
    }

    @Test
    public void testValidateIssuerFormatError() throws Exception {

        AuthnRequest request = getAuthnRequest();
        request.getIssuer().setFormat("Invalid-Issuer-Format");

        SAMLSSOReqValidationResponseDTO validationResp = executeValidate(request, true);
        assertFalse(validationResp.isValid(), "Authentication request validation should give invalid.");
        assertNotNull(validationResp.getResponse(), "Authentication request validation response should not be null.");
    }

    @Test
    public void testValidateSubjectConformationsExistError() throws Exception {

        AuthnRequest request = getAuthnRequest();

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

        AuthnRequest request = getAuthnRequest();
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
        AuthnRequest request = getAuthnRequest();
        SPInitSSOAuthnRequestValidator authnRequestValidator =
                (SPInitSSOAuthnRequestValidator) SAMLSSOUtil.getSPInitSSOAuthnRequestValidator(request);

        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.validateTenantDomain(anyString())).thenReturn(tenantDomain);

        String issuer = authnRequestValidator.splitAppendedTenantDomain(unsplittedIssuer);
        assertEquals(issuer, actualIssuer, "Should give the issuer without appended tenant domain.");
    }

    private SAMLSSOReqValidationResponseDTO executeValidate (AuthnRequest request, boolean shouldMakeSAMLIssuerExist)
            throws Exception {

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

    //TODO change this to use opensaml and build the Authentication Request form the beginning.
    private AuthnRequest getAuthnRequest() throws IdentityException {
        String decodedSamlReq = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<samlp:AuthnRequest AssertionConsumerServiceURL=\"http://localhost.com:8080/travelocity.com/home" +
                ".jsp\" Destination=\"https://localhost:9443/samlsso\" ForceAuthn=\"false\" ID=\"nniaelnagbnbmblg" +
                "afgllaeabebmbhiamedekagc\" IsPassive=\"false\" IssueInstant=\"2017-10-08T13:54:59.853Z\" Protocol" +
                "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\" xmlns:samlp=\"urn:oasi" +
                "s:names:tc:SAML:2.0:protocol\"><samlp:Issuer xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:assertion\"" +
                ">travelocity.com</samlp:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:" +
                "SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:" +
                "SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#nn" +
                "iaelnagbnbmblgafgllaeabebmbhiamedekagc\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3." +
                "org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/" +
                "xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#" +
                "sha1\"/><ds:DigestValue>2/4hltZllmyC5OUMQIaLDjkyF4A=</ds:DigestValue></ds:Reference></ds:" +
                "SignedInfo><ds:SignatureValue>iR6TyaWqegIGqTbz++KUWmrMqIV6rKQJL8mFy7CqkQ6vb4JRjqmqTFe7EbGocRop" +
                "+u2TSroGoqPEppL6wva+kRHa37+YhJChhaowS3a1IYcUL4iuEfvv2/55m4caGVQnVm/7q1WIZpOT7vb8jt9nq3Ek59RrVX1" +
                "O5wRNC46M+rvla4/qzMrsGIT9EF7z83P3mBbB48F7XhbxaRMq7mDm0j5AyvIwgSra/q4seLAT75x9fYxoXj2HHeZc3ZXWBSK" +
                "BGvdiB6mKB0peSqsc7xVae47L4whCpS05ejrSv4agaSGRsdO6Eino9cQngyv7Vr8IrtBo6d7jSWLFJN68d+qPRQ==</ds:" +
                "SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSTCCAjGgAwIBAgIEAoLQ/TANBgkqhki" +
                "G9w0BAQsFADBVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxDTALBgNVBAoTBF" +
                "dTTzIxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0xNzA3MTkwNjUyNTFaFw0yNzA3MTcwNjUyNTFaMFUxCzAJBgNVBAYTAlVTMQ" +
                "swCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzENMAsGA1UEChMEV1NPMjESMBAGA1UEAxMJbG9jYWxob3N0M" +
                "IIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAluZFdW1ynitztkWLC6xKegbRWxky+5P0p4ShYEOkHs30QI2VCuR6" +
                "Qo4Bz5rTgLBrky03W1GAVrZxuvKRGj9V9+PmjdGtau4CTXu9pLLcqnruaczoSdvBYA3lS9a7zgFU0+s6kMl2EhB+rk7gXlu" +
                "Eep7lIOenzfl2f6IoTKa2fVgVd3YKiSGsyL4tztS70vmmX121qm0sTJdKWP4HxXyqK9neolXI9fYyHOYILVNZ69z/73OOVh" +
                "kh/mvTmWZLM7GM6sApmyLX6OXUp8z0pkY+vT/9+zRxxQs7GurC4/C1nK3rI/0ySUgGEafO1atNjYmlFN+M3tZX6nEcA6g94" +
                "IavyQIDAQABoyEwHzAdBgNVHQ4EFgQUtS8kIYxQ8UVvVrZSdgyide9OHxUwDQYJKoZIhvcNAQELBQADggEBABfk5mqsVUrp" +
                "FCYTZZhOxTRRpGXqoW1G05bOxHxs42Paxw8rAJ06Pty9jqM1CgRPpqvZa2lPQBQqZrHkdDE06q4NG0DqMH8NT+tNkXBe9YTr" +
                "e3EJCSfsvswtLVDZ7GDvTHKojJjQvdVCzRj6XH5Truwefb4BJz9APtnlyJIvjHk1hdozqyOniVZd0QOxLAbcdt946chNdQvC" +
                "m6aUOputp8Xogr0KBnEy3U8es2cAfNZaEkPU8Va5bU6Xjny8zGQnXCXxPKp7sMpgO93nPBt/liX1qfyXM7xEotWoxmm6HZx8" +
                "oWQ8U5aiXjZ5RKDWCCq4ZuXl6wVsUz1iE61suO5yWi8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:" +
                "Signature><saml2p:NameIDPolicy AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-" +
                "format:persistent\" SPNameQualifier=\"Issuer\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:" +
                "protocol\"/><saml2p:RequestedAuthnContext Comparison=\"exact\" xmlns:saml2p=\"urn:oasis:names:" +
                "tc:SAML:2.0:protocol\"><saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:" +
                "assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:" +
                "AuthnContextClassRef></saml2p:RequestedAuthnContext></samlp:AuthnRequest>";
        return (AuthnRequest) SAMLSSOUtil.unmarshall(decodedSamlReq);
    }
}