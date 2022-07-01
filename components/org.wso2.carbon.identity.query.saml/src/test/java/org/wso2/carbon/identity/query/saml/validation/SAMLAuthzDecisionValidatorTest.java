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
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
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
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

import static org.testng.Assert.assertEquals;
import static org.wso2.carbon.identity.query.saml.validation.TestUtil.initPrivilegedCarbonContext;
import static org.wso2.carbon.identity.query.saml.validation.TestUtil.stopPrivilegedCarbonContext;

/**
 * Test Class for the SAMLAuthzDecisionValidator.
 */
@PrepareForTest({MultitenantUtils.class, SAMLQueryServiceComponent.class, SAMLQueryRequestUtil.class, OpenSAML3Util.class})
@PowerMockIgnore({"javax.xml.*", "org.xml.*", "org.w3c.dom.*"})
public class SAMLAuthzDecisionValidatorTest extends PowerMockTestCase {
    @Mock
    RealmService testRealmService;
    @Mock
    UserRealm testUserRealm;
    @Mock
    UserStoreManager testuserStoreManager;

    SAMLAuthzDecisionValidator testclass = new SAMLAuthzDecisionValidator();
    List<InvalidItemDTO> invalidItems = new ArrayList<>();

    @BeforeClass
    public void setUp() {

        initPrivilegedCarbonContext("testDomain", 1, "testuser");
    }

    @AfterClass
    public void tearDown() {

        stopPrivilegedCarbonContext();
    }

    @DataProvider(name = "provideAuthzDecisionQuery")
    public Object[][] createSubject() {

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

        DummyAuthDecisionQuery dumSQ1 = new DummyAuthDecisionQuery();
        DummyAuthDecisionQuery dumSQ2 = new DummyAuthDecisionQuery();
        DummyAuthDecisionQuery dumSQ3 = new DummyAuthDecisionQuery();
        DummyAuthDecisionQuery dumSQ4 = new DummyAuthDecisionQuery();

        dumSQ1.setSubject(dumSub1);
        dumSQ2.setSubject(dumSub2);
        dumSQ3.setSubject(dumSub3);
        dumSQ4.setSubject(dumSub4);

        dumSQ1.setIssuer(issuer1);
        dumSQ2.setIssuer(issuer2);
        dumSQ3.setIssuer(issuer3);
        dumSQ4.setIssuer(issuer4);

        dumSQ2.setactions();
        dumSQ4.setactions();

        dumSQ3.setResource("test");
        dumSQ4.setResource("test");
        dumSQ2.setResource("");

        dumSQ1.setVersion(SAMLVersion.VERSION_10);
        dumSQ2.setVersion(SAMLVersion.VERSION_20);
        dumSQ3.setVersion(SAMLVersion.VERSION_20);

        dumSQ4.setVersion(SAMLVersion.VERSION_20);
        return new Object[][]{
                {dumSQ1, false},
                {dumSQ2, false},
                {dumSQ3, false},
                {dumSQ4, true},
        };
    }

    @Test(dataProvider = "provideAuthzDecisionQuery")
    public void testValidate(Object dummy, boolean value) throws IdentitySAML2QueryException, UserStoreException {

        SAMLSSOServiceProviderDO ssoIdpConfigs = new SAMLSSOServiceProviderDO();
        ssoIdpConfigs.setNameIDFormat("test");
        ssoIdpConfigs.setCertAlias("test");
        ssoIdpConfigs.setAssertionQueryRequestProfileEnabled(true);
        mockStatic(SAMLQueryRequestUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(SAMLQueryServiceComponent.class);
        mockStatic(OpenSAML3Util.class);
        when(SAMLQueryRequestUtil.getServiceProviderConfig(anyString())).thenReturn(ssoIdpConfigs);
        when(OpenSAML3Util.validateXMLSignature((RequestAbstractType) any(), anyString(), anyString()))
                .thenReturn(true);
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("test");
        when(testRealmService.getTenantUserRealm(anyInt())).thenReturn(testUserRealm);
        when(testUserRealm.getUserStoreManager()).thenReturn(testuserStoreManager);
        when(SAMLQueryServiceComponent.getRealmservice()).thenReturn(testRealmService);
        when(testuserStoreManager.isExistingUser(anyString())).thenReturn(true);
        assertEquals(testclass.validate(invalidItems, (DummyAuthDecisionQuery) dummy), value);
    }

}
