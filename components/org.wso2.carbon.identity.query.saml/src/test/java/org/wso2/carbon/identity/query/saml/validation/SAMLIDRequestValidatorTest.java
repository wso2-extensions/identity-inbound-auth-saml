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
import org.opensaml.saml.saml2.core.AssertionIDRef;
import org.opensaml.saml.saml2.core.AssertionIDRequest;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.impl.AssertionIDRefImpl;
import org.opensaml.saml.saml2.core.impl.IssuerImpl;
import org.opensaml.saml.saml2.core.impl.ManageNameIDRequestImpl;
import org.opensaml.saml.saml2.core.impl.SubjectQueryImpl;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;
import static org.wso2.carbon.identity.query.saml.validation.TestUtil.initPrivilegedCarbonContext;
import static org.wso2.carbon.identity.query.saml.validation.TestUtil.stopPrivilegedCarbonContext;


/**
 * Test Class for the SAMLIDRequestValidator.
 */
@PrepareForTest({SAMLQueryRequestUtil.class, OpenSAML3Util.class})
@PowerMockIgnore({"java.net.*", "org.opensaml.*", "javax.xml.*", "org.xml.*", "org.w3c.dom.*"})
public class SAMLIDRequestValidatorTest extends PowerMockTestCase {

    SAMLIDRequestValidator testclass = new SAMLIDRequestValidator();

    @BeforeMethod
    public void setUp() throws Exception {

        initPrivilegedCarbonContext("testDomain", 1, "testuser");
    }

    @AfterMethod
    public void tearDown() {

        stopPrivilegedCarbonContext();
    }

    @Test
    public void testValidate() throws IdentitySAML2QueryException {

        DummyIssuer issuer5 = new DummyIssuer();
        DummyRequest request5 = new DummyRequest();
        request5.setVersion(SAMLVersion.VERSION_20);
        issuer5.setValue("test");
        issuer5.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        request5.setIssuer(issuer5);
        List<InvalidItemDTO> invalidItems = new ArrayList<>();
        SAMLSSOServiceProviderDO ssoIdpConfigs = new SAMLSSOServiceProviderDO();
        mockStatic(SAMLQueryRequestUtil.class);
        when(SAMLQueryRequestUtil.getServiceProviderConfig(anyString())).thenReturn(ssoIdpConfigs);
        mockStatic(OpenSAML3Util.class);
        ssoIdpConfigs.setCertAlias("test");
        ssoIdpConfigs.setAssertionQueryRequestProfileEnabled(true);
        when(OpenSAML3Util.validateXMLSignature((RequestAbstractType) any(), anyString(), anyString()))
                .thenReturn(true);
        assertFalse(testclass.validate(invalidItems, request5));
        request5.additem();
        assertTrue(testclass.validate(invalidItems, request5));
        when(OpenSAML3Util.validateXMLSignature((RequestAbstractType) any(), anyString(), anyString()))
                .thenReturn(false);
        assertFalse(testclass.validate(invalidItems, request5));
    }

    class DummyRequest extends ManageNameIDRequestImpl implements AssertionIDRequest {

        List<AssertionIDRef> testlist = new ArrayList<>();

        protected DummyRequest() {
            super("testNSU", "testELN", "testNSP");
        }

        @Override
        public List<AssertionIDRef> getAssertionIDRefs() {
            return testlist;
        }
        public void  additem(){
            DummyAssertion item = new DummyAssertion();
            testlist.add((AssertionIDRef) item);
        }
    }

    class DummyIssuer extends IssuerImpl {

        protected DummyIssuer() {
            super("testNSU", "testELN", "testNSP");
        }

    }

    class DummyAssertion extends AssertionIDRefImpl {

        protected DummyAssertion() {
            super("testNSU", "testELN", "testNSP");
        }
    }

}
