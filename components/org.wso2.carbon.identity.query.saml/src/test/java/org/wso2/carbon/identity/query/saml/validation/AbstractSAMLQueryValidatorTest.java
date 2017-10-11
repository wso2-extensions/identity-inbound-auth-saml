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

package org.wso2.carbon.identity.query.saml.validation;

import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.impl.IssuerImpl;
import org.opensaml.saml.saml2.core.impl.ManageNameIDRequestImpl;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.*;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.util.OpenSAML3Util;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.*;

/**
 * Test Class for the AbstractSAMLQueryValidator
 */
@PrepareForTest({SAMLQueryRequestUtil.class, OpenSAML3Util.class})
@PowerMockIgnore({"java.net.*", "org.opensaml.*"})
public class AbstractSAMLQueryValidatorTest extends PowerMockTestCase {
    AbstractSAMLQueryValidator testclass = new AbstractSAMLQueryValidator();
    SAMLAttributeQueryValidator testclass2 =new SAMLAttributeQueryValidator();
    @DataProvider(name = "providerequest")
    public Object[][] createSubject() {

        DummyIssuer issuer1 = new DummyIssuer();
        DummyIssuer issuer2 = new DummyIssuer();
        DummyIssuer issuer3 = new DummyIssuer();
        DummyIssuer issuer4 = new DummyIssuer();
        DummyRequest request1 = new DummyRequest();
        DummyRequest request2 = new DummyRequest();
        DummyRequest request3 = new DummyRequest();
        DummyRequest request4 = new DummyRequest();
        issuer2.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer3.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer4.setFormat("testformat");
        issuer2.setValue("failtest");
        issuer3.setValue("test");
        issuer1.setValue("failtest");
        issuer4.setValue("failtest");
        request1.setIssuer(issuer1);
        request2.setIssuer(issuer2);
        request3.setIssuer(issuer3);
        request4.setIssuer(issuer4);
        request1.setVersion(null);
        request2.setVersion(SAMLVersion.VERSION_11);
        request3.setVersion(SAMLVersion.VERSION_20);
        request4.setVersion(SAMLVersion.VERSION_10);
        return new Object[][]{
                {request1, false},
                {request2, false},
                {request3, true},
                {request4, false},
        };
    }

    @DataProvider(name = "provideValidationRequest")
    public Object[][] createRequest() {

        DummyIssuer issuer1 = new DummyIssuer();
        DummyIssuer issuer2 = new DummyIssuer();
        DummyIssuer issuer3 = new DummyIssuer();
        DummyIssuer issuer4 = new DummyIssuer();
        DummyIssuer issuer5 = new DummyIssuer();
        DummyRequest request1 = new DummyRequest();
        DummyRequest request2 = new DummyRequest();
        DummyRequest request3 = new DummyRequest();
        DummyRequest request4 = new DummyRequest();
        DummyRequest request5 = new DummyRequest();
        request1.setVersion(null);
        request2.setVersion(SAMLVersion.VERSION_20);
        request3.setVersion(SAMLVersion.VERSION_20);
        request4.setVersion(SAMLVersion.VERSION_20);
        request5.setVersion(SAMLVersion.VERSION_20);
        issuer2.setValue("failtest");
        issuer3.setValue("failtest");
        issuer4.setValue("failtest");
        issuer5.setValue("test");
        issuer2.setFormat("failtestformat");
        issuer3.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer4.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer5.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        request1.setIssuer(issuer1);
        request2.setIssuer(issuer2);
        request3.setIssuer(issuer3);
        request4.setIssuer(issuer4);
        request5.setIssuer(issuer5);
        return new Object[][]{
                {request1, false, false},
                {request2, false, false},
                {request3, false, false},
                {request4, false, true},
                {request5, true, true},
        };
    }

    @Test(dataProvider = "provideValidationRequest")
    public void testValidate(Object request, boolean value, boolean assertEn) throws Exception {

        List<InvalidItemDTO> invalidItems = new ArrayList<>();
        SAMLSSOServiceProviderDO ssoIdpConfigs = new SAMLSSOServiceProviderDO();
        mockStatic(SAMLQueryRequestUtil.class);
        when(SAMLQueryRequestUtil.getServiceProviderConfig(anyString())).thenReturn(ssoIdpConfigs);
        mockStatic(OpenSAML3Util.class);
        ssoIdpConfigs.setCertAlias("test");
        ssoIdpConfigs.setAssertionQueryRequestProfileEnabled(false);
        if (assertEn) {
            ssoIdpConfigs.setAssertionQueryRequestProfileEnabled(true);
        }
        when(OpenSAML3Util.validateXMLSignature((RequestAbstractType) any(), anyString(), anyString())).thenReturn(false);
        if (value) {
            when(OpenSAML3Util.validateXMLSignature((RequestAbstractType) any(), anyString(), anyString()))
                    .thenReturn(true);
        }
        assertEquals(testclass.validate(invalidItems, (RequestAbstractType) request),value);
    }

    @Test
    public void testValidateSignature() throws Exception {

        setSAMLprovider();
        mockStatic(OpenSAML3Util.class);
        when(OpenSAML3Util.validateXMLSignature((RequestAbstractType) any(), anyString(), anyString())).thenReturn(true);
        DummyRequest request = new DummyRequest();
        assertTrue(testclass.validateSignature(request));
        when(OpenSAML3Util.validateXMLSignature((RequestAbstractType) any(), anyString(), anyString())).thenReturn(false);
        assertFalse(testclass.validateSignature(request));
    }

    @BeforeClass
    public void setUp() throws Exception {

        initPrivilegedCarbonContext("testDomain", 1, "testuser");
    }

    @Test(dataProvider = "providerequest")
    public void testValidateIssuer(Object request, boolean value) throws Exception {

        SAMLSSOServiceProviderDO ssoIdpConfigs = new SAMLSSOServiceProviderDO();
        mockStatic(SAMLQueryRequestUtil.class);
        when(SAMLQueryRequestUtil.getServiceProviderConfig("test")).thenReturn(ssoIdpConfigs);
        assertEquals(testclass.validateIssuer((RequestAbstractType) request), value);
    }

    @AfterClass
    public void tearDown() throws Exception {

        System.clearProperty(CarbonBaseConstants.CARBON_HOME);
    }

    @Test(dataProvider = "providerequest")
    public void testValidateSAMLVersion(Object request, boolean value) throws Exception {

        assertEquals(testclass.validateSAMLVersion((RequestAbstractType) request), value);
    }

    class DummyRequest extends ManageNameIDRequestImpl {

        protected DummyRequest() {
            super("testNSU", "testELN", "testNSP");
        }
    }

    class DummyIssuer extends IssuerImpl {

        protected DummyIssuer() {
            super("testNSU", "testELN", "testNSP");
        }

    }

    private void setSAMLprovider() throws IdentitySAML2QueryException {

        SAMLSSOServiceProviderDO ssoIdpConfigs = new SAMLSSOServiceProviderDO();
        mockStatic(SAMLQueryRequestUtil.class);
        when(SAMLQueryRequestUtil.getServiceProviderConfig("test")).thenReturn(ssoIdpConfigs);
        ssoIdpConfigs.setCertAlias("test");
        ssoIdpConfigs.setAssertionQueryRequestProfileEnabled(true);
        DummyIssuer issuert = new DummyIssuer();
        DummyRequest requestt = new DummyRequest();
        issuert.setValue("test");
        issuert.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        requestt.setIssuer(issuert);
        testclass.validateIssuer(requestt);
    }

    private void initPrivilegedCarbonContext(String tenantDomain, int tenantID, String userName) throws Exception {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
    }

}