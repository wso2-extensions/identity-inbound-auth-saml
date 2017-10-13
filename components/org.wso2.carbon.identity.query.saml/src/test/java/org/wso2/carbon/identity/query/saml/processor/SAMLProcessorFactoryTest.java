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

package org.wso2.carbon.identity.query.saml.processor;

import org.opensaml.saml.saml2.core.impl.*;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Test Class for the SAMLProcessorFactory
 */
public class SAMLProcessorFactoryTest {

    @DataProvider(name = "requestProvider")
    public Object[][] createRequest() {
        DummyAssertionIDRequest dummy1 = new DummyAssertionIDRequest();
        DummyAttributeQueryImpl dummy2 = new DummyAttributeQueryImpl();
        DummyAuthnQueryImpl dummy3 = new DummyAuthnQueryImpl();
        DummyAuthzDecisionQueryImpl dummy4 = new DummyAuthzDecisionQueryImpl();
        DummySubjectQueryImpl dummy5 = new DummySubjectQueryImpl();
        DummyLogoutRequestImpl dummy6 =new DummyLogoutRequestImpl();
        return new Object[][]{
                {dummy1, 1},
                {dummy2, 2},
                {dummy3, 3},
                {dummy4, 4},
                {dummy5, 5},
                {dummy6, 6},
        };
    }

    @Test(dataProvider = "requestProvider")
    public void testGetProcessor(Object dumrequest, int value) throws Exception {

        if (value == 1) {
            assertTrue(SAMLProcessorFactory.getProcessor((DummyAssertionIDRequest) dumrequest)
                    instanceof SAMLIDRequestProcessor);
        } else if (value == 2) {
            assertTrue(SAMLProcessorFactory.getProcessor((DummyAttributeQueryImpl) dumrequest)
                    instanceof SAMLAttributeQueryProcessor);
        } else if (value == 3) {
            assertTrue(SAMLProcessorFactory.getProcessor((DummyAuthnQueryImpl) dumrequest)
                    instanceof SAMLAuthnQueryProcessor);
        } else if (value == 4) {
            assertTrue(SAMLProcessorFactory.getProcessor((DummyAuthzDecisionQueryImpl) dumrequest)
                    instanceof SAMLAuthzDecisionProcessor);
        } else if (value == 5) {
            assertTrue(SAMLProcessorFactory.getProcessor((DummySubjectQueryImpl) dumrequest)
                    instanceof SAMLSubjectQueryProcessor);
        }else{
            assertEquals(SAMLProcessorFactory.getProcessor((DummyLogoutRequestImpl) dumrequest),null);
        }

    }

    class DummyAssertionIDRequest extends AssertionIDRequestImpl {

        protected DummyAssertionIDRequest() {
            super("testNSU", "testELN", "testNSP");
        }
    }

    class DummyAttributeQueryImpl extends AttributeQueryImpl {

        protected DummyAttributeQueryImpl() {
            super("testNSU", "testELN", "testNSP");
        }
    }

    class DummyAuthnQueryImpl extends AuthnQueryImpl {

        protected DummyAuthnQueryImpl() {
            super("testNSU", "testELN", "testNSP");
        }
    }

    class DummyAuthzDecisionQueryImpl extends AuthzDecisionQueryImpl {

        protected DummyAuthzDecisionQueryImpl() {
            super("testNSU", "testELN", "testNSP");
        }
    }

    class DummySubjectQueryImpl extends SubjectQueryImpl {

        protected DummySubjectQueryImpl() {
            super("testNSU", "testELN", "testNSP");
        }
    }

    class DummyLogoutRequestImpl extends LogoutRequestImpl {

        protected DummyLogoutRequestImpl() {
            super("testNSU", "testELN", "testNSP");
        }
    }

}
