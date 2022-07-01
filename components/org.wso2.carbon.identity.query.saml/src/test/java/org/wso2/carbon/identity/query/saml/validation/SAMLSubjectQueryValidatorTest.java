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
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.impl.IssuerImpl;
import org.opensaml.saml.saml2.core.impl.NameIDImpl;
import org.opensaml.saml.saml2.core.impl.SubjectImpl;
import org.opensaml.saml.saml2.core.impl.SubjectQueryImpl;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
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
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
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

import static org.testng.AssertJUnit.assertEquals;
import static org.wso2.carbon.identity.query.saml.validation.TestUtil.initPrivilegedCarbonContext;
import static org.wso2.carbon.identity.query.saml.validation.TestUtil.stopPrivilegedCarbonContext;


/**
 * Test Class for the SAMLSubjectQueryValidator.
 */
@PrepareForTest({MultitenantUtils.class, SAMLQueryServiceComponent.class, SAMLQueryRequestUtil.class, OpenSAML3Util.class})
@PowerMockIgnore({"javax.xml.*", "org.xml.*", "org.w3c.dom.*"})
public class SAMLSubjectQueryValidatorTest extends PowerMockTestCase {

    @Mock
    RealmService testRealmService;
    @Mock
    UserRealm testUserRealm;
    @Mock
    UserStoreManager testuserStoreManager;

    SAMLSubjectQueryValidator testsamlSubjectQueryValidator = new SAMLSubjectQueryValidator();
    List<InvalidItemDTO> invalidItems = new ArrayList<>();

    @BeforeClass
    public void setUp() {

        initPrivilegedCarbonContext("testDomain", 1, "testuser");
    }

    @AfterClass
    public void tearDown() {

        stopPrivilegedCarbonContext();
    }


    @DataProvider(name = "provideSubectQuery")
    public Object[][] createSubjectQuery() {

        DummyNameID dumID1 = new DummyNameID();
        DummyNameID dumID2 = new DummyNameID();
        DummyNameID dumID3 = new DummyNameID();

        dumID1.setFormat("failtest");
        dumID2.setFormat("test");

        DummySubject dumSub1 = new DummySubject();
        DummySubject dumSub2 = new DummySubject();
        DummySubject dumSub3 = new DummySubject();

        DummySubject dumSub4 = new DummySubject();
        dumSub2.setNameID(dumID1);
        dumSub3.setNameID(dumID2);
        dumSub4.setNameID(dumID3);

        DummyIssuer issuer1 = new DummyIssuer();
        DummyIssuer issuer2 = new DummyIssuer();
        DummyIssuer issuer3 = new DummyIssuer();
        DummyIssuer issuer4 = new DummyIssuer();
        DummyIssuer issuer5 = new DummyIssuer();

        DummyIssuer issuer6 = new DummyIssuer();
        issuer1.setValue("test");
        issuer2.setValue("test");
        issuer3.setValue("test");
        issuer4.setValue("test");
        issuer5.setValue("test");
        issuer6.setValue("test");

        issuer1.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer2.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer3.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer4.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer5.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);
        issuer6.setFormat(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT);

        DummySubjectQuery dumSQ1 = new DummySubjectQuery();
        DummySubjectQuery dumSQ2 = new DummySubjectQuery();
        DummySubjectQuery dumSQ3 = new DummySubjectQuery();
        DummySubjectQuery dumSQ4 = new DummySubjectQuery();
        DummySubjectQuery dumSQ5 = new DummySubjectQuery();
        DummySubjectQuery dumSQ6 = new DummySubjectQuery();

        dumSQ2.setSubject(dumSub1);
        dumSQ3.setSubject(dumSub2);
        dumSQ4.setSubject(dumSub3);
        dumSQ5.setSubject(dumSub4);

        dumSQ1.setIssuer(issuer1);
        dumSQ2.setIssuer(issuer2);
        dumSQ3.setIssuer(issuer3);
        dumSQ4.setIssuer(issuer4);
        dumSQ5.setIssuer(issuer5);
        dumSQ6.setIssuer(issuer6);

        dumSQ1.setVersion(SAMLVersion.VERSION_20);
        dumSQ2.setVersion(SAMLVersion.VERSION_20);
        dumSQ3.setVersion(SAMLVersion.VERSION_20);
        dumSQ4.setVersion(SAMLVersion.VERSION_20);
        dumSQ5.setVersion(SAMLVersion.VERSION_20);
        dumSQ6.setVersion(SAMLVersion.VERSION_10);

        SAMLSSOServiceProviderDO ssoIdpConfigs1 = new SAMLSSOServiceProviderDO();
        SAMLSSOServiceProviderDO ssoIdpConfigs2 = new SAMLSSOServiceProviderDO();
        ssoIdpConfigs1.setCertAlias("test");
        ssoIdpConfigs1.setAssertionQueryRequestProfileEnabled(true);

        ssoIdpConfigs2.setNameIDFormat("test");
        ssoIdpConfigs2.setCertAlias("test");
        ssoIdpConfigs2.setAssertionQueryRequestProfileEnabled(true);
        return new Object[][]{
                {dumSQ1, false, ssoIdpConfigs2},
                {dumSQ6, false, ssoIdpConfigs2},
                {dumSQ2, false, ssoIdpConfigs2},
                {dumSQ3, false, ssoIdpConfigs2},
                {dumSQ4, false, ssoIdpConfigs1},
                {dumSQ5, false, ssoIdpConfigs2},
                {dumSQ4, false, ssoIdpConfigs2},
                {dumSQ4, true, ssoIdpConfigs2}
        };
    }

    @Test(dataProvider = "provideSubectQuery")
    public void testValidate(Object SubQ, boolean expectedValue, Object SAMLSSOServiceProviderDO)
            throws IdentitySAML2QueryException, org.wso2.carbon.user.api.UserStoreException {

        mockStatic(SAMLQueryRequestUtil.class);
        mockStatic(MultitenantUtils.class);
        mockStatic(SAMLQueryServiceComponent.class);
        mockStatic(OpenSAML3Util.class);
        when(SAMLQueryRequestUtil.getServiceProviderConfig(anyString())).thenReturn((SAMLSSOServiceProviderDO) SAMLSSOServiceProviderDO);
        when(OpenSAML3Util.validateXMLSignature((RequestAbstractType) any(), anyString(), anyString()))
                .thenReturn(true);
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("test");
        when(testuserStoreManager.isExistingUser(anyString())).thenReturn(false);
        if (expectedValue) {
            when(testuserStoreManager.isExistingUser(anyString())).thenReturn(true);
        }
        when(testRealmService.getTenantUserRealm(anyInt())).thenReturn(testUserRealm);
        when(testUserRealm.getUserStoreManager()).thenReturn(testuserStoreManager);
        when(SAMLQueryServiceComponent.getRealmservice()).thenReturn(testRealmService);

        assertEquals(testsamlSubjectQueryValidator.validate(invalidItems, (DummySubjectQuery) SubQ), expectedValue);
    }

    @Test
    public void testUserStoreExceptionforValidate()
            throws IdentitySAML2QueryException, org.wso2.carbon.user.api.UserStoreException {

        DummyNameID dumID2 = new DummyNameID();
        DummySubject dumSub = new DummySubject();
        DummySubjectQuery dumSQ2 = new DummySubjectQuery();
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
        when(testuserStoreManager.isExistingUser(anyString())).thenThrow(new UserStoreException());
        testsamlSubjectQueryValidator.validate(invalidItems, dumSQ2);
    }

    class DummySubjectQuery extends SubjectQueryImpl {

        protected DummySubjectQuery() {
            super("testNSU", "testELN", "testNSP");
        }

        Subject subject;

        @Override
        public void setSubject(Subject subject) {
            this.subject = subject;
        }

        @Override
        public Subject getSubject() {
            return subject;
        }
    }

    class DummySubject extends SubjectImpl {

        protected DummySubject() {
            super("testNSU", "testELN", "testNSP");
        }

        NameID nameID;

        @Override
        public void setNameID(NameID newNameID) {
            nameID = newNameID;
        }

        @Override
        public NameID getNameID() {
            return nameID;
        }
    }

    class DummyNameID extends NameIDImpl {

        protected DummyNameID() {
            super("testNSU", "testELN", "testNSP");
        }

        String format;
        String value;

        @Override
        public void setFormat(String newFormat) {
            format = newFormat;
            value = newFormat;
        }

        @Override
        public String getFormat() {
            return format;
        }

        @Override
        public String getValue() {
            return value;
        }
    }

    class DummyIssuer extends IssuerImpl {

        protected DummyIssuer() {
            super("testNSU", "testELN", "testNSP");
        }

    }

}
