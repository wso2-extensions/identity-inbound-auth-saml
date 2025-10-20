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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.internal.SAMLQueryServiceComponent;
import org.wso2.carbon.identity.query.saml.util.OpenSAML3Util;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import static org.testng.AssertJUnit.assertEquals;
import static org.wso2.carbon.identity.query.saml.validation.TestUtil.initPrivilegedCarbonContext;
import static org.wso2.carbon.identity.query.saml.validation.TestUtil.stopPrivilegedCarbonContext;

/**
 * Test Class for the SAMLAuthQueryValidator.
 */
public class SAMLAuthQueryValidatorTest {

    @Mock
    RealmService testRealmService;
    @Mock
    UserRealm testUserRealm;
    @Mock
    UserStoreManager testuserStoreManager;

    AutoCloseable mocksHandle;

    SAMLAuthQueryValidator testclass = new SAMLAuthQueryValidator();
    List<InvalidItemDTO> invalidItems = new ArrayList<>();

    @BeforeClass
    public void setUp() {

        initPrivilegedCarbonContext("testDomain", 1, "testuser");
        mocksHandle = MockitoAnnotations.openMocks(this);
    }

    @AfterClass
    public void tearDown() throws Exception {

        stopPrivilegedCarbonContext();
        if (mocksHandle != null) {
            mocksHandle.close();
        }
    }

    @DataProvider(name = "provideAuthn")
    public Object[][] createAuthnQuery() {

        DummyNameID dumID1 = new DummyNameID();
        DummyNameID dumID2 = new DummyNameID();
        DummyNameID dumID3 = new DummyNameID();
        DummyNameID dumID4 = new DummyNameID();
        DummyNameID dumID5 = new DummyNameID();

        dumID1.setFormat("failtest");
        dumID2.setFormat("test");
        dumID3.setFormat("test");
        dumID4.setFormat("test");
        dumID5.setFormat("test");

        DummySubject dumSub1 = new DummySubject();
        DummySubject dumSub2 = new DummySubject();
        DummySubject dumSub3 = new DummySubject();
        DummySubject dumSub4 = new DummySubject();
        DummySubject dumSub5 = new DummySubject();

        dumSub1.setNameID(dumID1);
        dumSub2.setNameID(dumID2);
        dumSub3.setNameID(dumID3);
        dumSub4.setNameID(dumID4);
        dumSub5.setNameID(dumID5);

        DummyIssuer issuer1 = new DummyIssuer();
        DummyIssuer issuer2 = new DummyIssuer();
        DummyIssuer issuer3 = new DummyIssuer();
        DummyIssuer issuer4 = new DummyIssuer();
        DummyIssuer issuer5 = new DummyIssuer();

        issuer1.setValue("test");
        issuer2.setValue("test");
        issuer3.setValue("test");
        issuer4.setValue("test");
        issuer5.setValue("test");

        issuer1.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer2.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer3.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer4.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer5.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);

        dummyAuthnQueryImpl dumSQ1 = new dummyAuthnQueryImpl();
        dummyAuthnQueryImpl dumSQ2 = new dummyAuthnQueryImpl();
        dummyAuthnQueryImpl dumSQ3 = new dummyAuthnQueryImpl();
        dummyAuthnQueryImpl dumSQ4 = new dummyAuthnQueryImpl();
        dummyAuthnQueryImpl dumSQ5 = new dummyAuthnQueryImpl();

        dumSQ1.setSubject(dumSub1);
        dumSQ2.setSubject(dumSub2);
        dumSQ3.setSubject(dumSub3);
        dumSQ4.setSubject(dumSub4);
        dumSQ5.setSubject(dumSub5);

        dumSQ1.setIssuer(issuer1);
        dumSQ2.setIssuer(issuer2);
        dumSQ3.setIssuer(issuer3);
        dumSQ4.setIssuer(issuer4);
        dumSQ5.setIssuer(issuer5);

        dumSQ1.setVersion(SAMLVersion.VERSION_10);
        dumSQ2.setVersion(SAMLVersion.VERSION_20);
        dumSQ3.setVersion(SAMLVersion.VERSION_20);
        dumSQ4.setVersion(SAMLVersion.VERSION_20);
        dumSQ5.setVersion(SAMLVersion.VERSION_20);

        dumSQ2.setSessionIndex(null);
        dumSQ3.setSessionIndex("testindex");
        dumSQ4.setSessionIndex("");
        dumSQ5.setSessionIndex("testindex");

        DummyReqAuthnContext dummyAuthContext2 = new DummyReqAuthnContext();
        DummyReqAuthnContext dummyAuthContext3 = new DummyReqAuthnContext();
        DummyReqAuthnContext dummyAuthContext4 = new DummyReqAuthnContext();
        DummyReqAuthnContext dummyAuthContext5 = new DummyReqAuthnContext();

        dummyAuthContext2.setAuthnContextClassRefs();
        dummyAuthContext5.setAuthnContextClassRefs();

        dumSQ2.setRequestedAuthnContext(dummyAuthContext2);
        dumSQ3.setRequestedAuthnContext(dummyAuthContext3);
        dumSQ4.setRequestedAuthnContext(dummyAuthContext4);
        dumSQ5.setRequestedAuthnContext(dummyAuthContext5);

        return new Object[][]{
                {dumSQ1, false},
                {dumSQ2, true},
                {dumSQ3, true},
                {dumSQ4, false},
                {dumSQ5, true},
        };
    }


    @Test(dataProvider = "provideAuthn")
    public void testValidate(Object dummy, boolean expectedValue) throws IdentitySAML2QueryException, UserStoreException {

        SAMLSSOServiceProviderDO ssoIdpConfigs = new SAMLSSOServiceProviderDO();
        ssoIdpConfigs.setNameIDFormat("test");
        ssoIdpConfigs.setCertAlias("test");
        ssoIdpConfigs.setAssertionQueryRequestProfileEnabled(true);
        try (MockedStatic<SAMLQueryRequestUtil> samlQueryReqUtil = mockStatic(SAMLQueryRequestUtil.class);
             MockedStatic<MultitenantUtils> mt = mockStatic(MultitenantUtils.class);
             MockedStatic<SAMLQueryServiceComponent> samlQuerySvc = mockStatic(SAMLQueryServiceComponent.class);
             MockedStatic<OpenSAML3Util> openSaml3Util = mockStatic(OpenSAML3Util.class)) {
            samlQueryReqUtil.when(() -> SAMLQueryRequestUtil.getServiceProviderConfig(anyString()))
                    .thenReturn(ssoIdpConfigs);
            openSaml3Util.when(() -> OpenSAML3Util.validateXMLSignature((RequestAbstractType) any(), anyString(),
                            anyString())).thenReturn(true);
            mt.when(() -> MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("test");
            when(testRealmService.getTenantUserRealm(anyInt())).thenReturn(testUserRealm);
            when(testUserRealm.getUserStoreManager()).thenReturn(testuserStoreManager);
            samlQuerySvc.when(SAMLQueryServiceComponent::getRealmservice).thenReturn(testRealmService);
            when(testuserStoreManager.isExistingUser(anyString())).thenReturn(true);
            assertEquals(testclass.validate(invalidItems, (dummyAuthnQueryImpl) dummy), expectedValue);
        }
    }

}
