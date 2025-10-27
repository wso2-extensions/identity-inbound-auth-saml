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

import org.mockito.MockedStatic;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.query.saml.validation.TestUtil.initPrivilegedCarbonContext;
import static org.wso2.carbon.identity.query.saml.validation.TestUtil.stopPrivilegedCarbonContext;


/**
 * Test Class for the SAMLAttributeQueryValidator.
 */
public class SAMLAttributeQueryValidatorTest {

    RealmService testRealmService;
    UserRealm testUserRealm;
    UserStoreManager testuserStoreManager;

    SAMLAttributeQueryValidator testclass = new SAMLAttributeQueryValidator();
    List<InvalidItemDTO> invalidItems = new ArrayList<>();

    @BeforeClass
    public void setUp() {

        initPrivilegedCarbonContext("testDomain", 1, "testuser");
        testRealmService = mock(RealmService.class);
        testUserRealm = mock(UserRealm.class);
        testuserStoreManager = mock(UserStoreManager.class);
    }

    @AfterClass
    public void tearDown() {

        stopPrivilegedCarbonContext();
    }

    @Test
    public void testValidate() throws IdentitySAML2QueryException, UserStoreException {

        DummyNameID dumID2 = new DummyNameID();
        DummySubject dumSub = new DummySubject();
        DummySubjectQueryImpl dumSQ2 = new DummySubjectQueryImpl();
        dumID2.setFormat("test");
        dumSub.setNameID(dumID2);
        dumSQ2.setSubject(dumSub);
        DummyIssuer issuer = new DummyIssuer();
        issuer.setValue("test");
        issuer.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        dumSQ2.setIssuer(issuer);
        dumSQ2.setVersion(SAMLVersion.VERSION_20);
        SAMLSSOServiceProviderDO ssoIdpConfigs = new SAMLSSOServiceProviderDO();
        ssoIdpConfigs.setNameIDFormat("test");
        ssoIdpConfigs.setCertAlias("test");
        ssoIdpConfigs.setAssertionQueryRequestProfileEnabled(true);

        try (MockedStatic<SAMLQueryRequestUtil> samlQueryReqUtil = mockStatic(SAMLQueryRequestUtil.class);
             MockedStatic<MultitenantUtils> mt = mockStatic(MultitenantUtils.class);
             MockedStatic<SAMLQueryServiceComponent> comp = mockStatic(SAMLQueryServiceComponent.class);
             MockedStatic<OpenSAML3Util> openSaml3Util = mockStatic(OpenSAML3Util.class)) {

            samlQueryReqUtil.when(() -> SAMLQueryRequestUtil.getServiceProviderConfig(anyString()))
                    .thenReturn(ssoIdpConfigs);
            openSaml3Util.when(()->OpenSAML3Util.validateXMLSignature((RequestAbstractType) any(), anyString(),
                            anyString())).thenReturn(true);
            mt.when(() -> MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("test");
            when(testRealmService.getTenantUserRealm(anyInt())).thenReturn(testUserRealm);
            when(testUserRealm.getUserStoreManager()).thenReturn(testuserStoreManager);
            comp.when(SAMLQueryServiceComponent::getRealmservice).thenReturn(testRealmService);
            when(testuserStoreManager.isExistingUser(anyString())).thenReturn(true);
            testclass.validate(invalidItems, dumSQ2);
        }
    }

}
