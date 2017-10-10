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
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.AuthnQueryImpl;
import org.opensaml.saml.saml2.core.impl.NameIDImpl;
import org.opensaml.saml.saml2.core.impl.SubjectImpl;
import org.opensaml.saml.saml2.core.impl.SubjectQueryImpl;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.internal.SAMLQueryServiceComponent;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;


import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.*;

@PrepareForTest({MultitenantUtils.class,SAMLQueryServiceComponent.class})
public class SAMLSubjectQueryValidatorTest extends PowerMockTestCase{
    @Mock
    SAMLSubjectQueryValidator testsamlSubjectQueryValidator;
    @Mock
    SAMLQueryServiceComponent samlQueryServiceComponent;

    @Test
    public void testValidate() throws Exception {
        List<InvalidItemDTO> invalidItems =new ArrayList<>();
        RequestAbstractType request=null;
        when(((AbstractSAMLQueryValidator)testsamlSubjectQueryValidator).validate(invalidItems,request)).thenReturn(true);
        Boolean ans =testsamlSubjectQueryValidator.validate(invalidItems,request);
        System.out.println(ans);
    }
    @DataProvider(name = "provideSubectQuery")
    public Object[][] createSubject() {
        DummyNameID dumID1=new DummyNameID();
        DummyNameID dumID2=new DummyNameID();
        DummyNameID dumID3=new DummyNameID();
        dumID2.setFormat("test");
        dumID3.setFormat("failtest");
        DummySubject dumSub=new DummySubject();
        DummySubjectQuery dumSQ1 =new DummySubjectQuery();
        DummySubjectQuery dumSQ2 =new DummySubjectQuery();
        dumSQ2.setSubject(dumSub);
        DummySubjectQuery dumSQ3 =new DummySubjectQuery();
        dumSub.setNameID(dumID1);
        dumSQ3.setSubject(dumSub);
        DummySubjectQuery dumSQ4 =new DummySubjectQuery();
        dumSub.setNameID(dumID2);
        dumSQ4.setSubject(dumSub);
        DummySubjectQuery dumSQ5 =new DummySubjectQuery();
        dumSub.setNameID(dumID3);
        dumSQ5.setSubject(dumSub);
        return new Object[][]{
//                {dumSQ1,false},
//                {dumSQ2,false},
//                {dumSQ3,false},
                {dumSQ4,true},
//                {dumSQ5,false}
        };
    }

    @Test(dataProvider = "provideSubectQuery")
    public void testValidateSubject(Object dum, Object value) throws Exception {
        RealmService testRealmService= mock(RealmService.class, Mockito.CALLS_REAL_METHODS);
        UserRealm testUserRealm = mock(UserRealm.class, Mockito.CALLS_REAL_METHODS);
        UserStoreManager testuserStoreManager =mock(UserStoreManager.class, Mockito.CALLS_REAL_METHODS);
        SAMLSSOServiceProviderDO samlssoServiceProviderDO =mock(SAMLSSOServiceProviderDO.class,Mockito.CALLS_REAL_METHODS);

        mockStatic(MultitenantUtils.class);
        mockStatic(SAMLQueryServiceComponent.class);

        when(MultitenantUtils.getTenantAwareUsername("test")).thenReturn("test");
        when(MultitenantUtils.getTenantAwareUsername("failtest")).thenReturn("failtest");
        when(testuserStoreManager.isExistingUser("test")).thenReturn(true);
        when(testuserStoreManager.isExistingUser("failtest")).thenReturn(false);
        when(testRealmService.getTenantUserRealm(anyInt())).thenReturn(testUserRealm);
        when(SAMLQueryServiceComponent.getRealmservice()).thenReturn(testRealmService);
        when(samlssoServiceProviderDO.getNameIDFormat()).thenReturn("test");
        when(((AbstractSAMLQueryValidator)testsamlSubjectQueryValidator).getSsoIdpConfig()).thenReturn(samlssoServiceProviderDO);

        assertEquals(testsamlSubjectQueryValidator.validateSubject((DummySubjectQuery) dum),value);





    }

    class DummySubjectQuery extends SubjectQueryImpl{

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
    class DummySubject extends SubjectImpl{

        protected DummySubject() {
            super("testNSU", "testELN", "testNSP");
        }

        NameID nameID;
        @Override
        public void setNameID(NameID newNameID) {
            nameID=newNameID;
        }

        @Override
        public NameID getNameID() {
            return nameID;
        }
    }
    class DummyNameID extends NameIDImpl{

        protected DummyNameID() {
            super("testNSU", "testELN", "testNSP");
        }
        String format;
        String value;
        @Override
        public void setFormat(String newFormat) {
            format =newFormat;
            value=newFormat;
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

}