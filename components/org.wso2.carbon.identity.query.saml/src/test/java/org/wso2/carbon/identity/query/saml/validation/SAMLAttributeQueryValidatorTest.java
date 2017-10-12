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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
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

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.wso2.carbon.identity.query.saml.validation.TestUtil.*;

import static org.testng.Assert.*;

/**
 * Test Class for the SAMLAttributeQueryValidator
 */
@PrepareForTest({MultitenantUtils.class, SAMLQueryServiceComponent.class, SAMLQueryRequestUtil.class, OpenSAML3Util.class})
public class SAMLAttributeQueryValidatorTest extends PowerMockTestCase {

    @Mock
    RealmService testRealmService;
    @Mock
    UserRealm testUserRealm;
    @Mock
    UserStoreManager testuserStoreManager;

    SAMLAttributeQueryValidator testclass = new SAMLAttributeQueryValidator();
    List<InvalidItemDTO> invalidItems = new ArrayList<>();

    @BeforeClass
    public void setUp() {

        initPrivilegedCarbonContext("testDomain", 1, "testuser");
    }

    @AfterClass
    public void tearDown() {

        System.clearProperty(CarbonBaseConstants.CARBON_HOME);
    }

    @Test
    public void testValidate() throws IdentitySAML2QueryException, UserStoreException {

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
        when(testuserStoreManager.isExistingUser(anyString())).thenReturn(true);
        testclass.validate(invalidItems, dumSQ2);
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