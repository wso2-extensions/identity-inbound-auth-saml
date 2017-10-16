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


import org.opensaml.saml.saml2.core.impl.AssertionIDRequestImpl;
import org.opensaml.saml.saml2.core.impl.AttributeQueryImpl;
import org.opensaml.saml.saml2.core.impl.AuthnQueryImpl;
import org.opensaml.saml.saml2.core.impl.AuthzDecisionQueryImpl;
import org.opensaml.saml.saml2.core.impl.LogoutRequestImpl;
import org.opensaml.saml.saml2.core.impl.SubjectQueryImpl;
import org.testng.annotations.Test;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;


/**
 * Test Class for the SAMLProcessorFactory.
 */
public class SAMLProcessorFactoryTest {

    @Test
    public void testGetProcessorForSAMLIDRequest() {


        DummyAssertionIDRequest dummy = new DummyAssertionIDRequest();
        assertTrue(SAMLProcessorFactory.getProcessor(dummy) instanceof SAMLIDRequestProcessor);
    }

    @Test
    public void testGetProcessorForAttributeQueryImpl() {

        DummyAttributeQueryImpl dummy = new DummyAttributeQueryImpl();
        assertTrue(SAMLProcessorFactory.getProcessor(dummy) instanceof SAMLAttributeQueryProcessor);
    }

    @Test
    public void testGetProcessorForAuthnQueryImpl() {

        DummyAuthnQueryImpl dummy = new DummyAuthnQueryImpl();
        assertTrue(SAMLProcessorFactory.getProcessor(dummy) instanceof SAMLAuthnQueryProcessor);
    }

    @Test
    public void testGetProcessorForAuthzDecisionQueryImpl() {

        DummyAuthzDecisionQueryImpl dummy = new DummyAuthzDecisionQueryImpl();
        assertTrue(SAMLProcessorFactory.getProcessor(dummy) instanceof SAMLAuthzDecisionProcessor);
    }

    @Test
    public void testGetProcessorForSubjectQueryImpl() {

        DummySubjectQueryImpl dummy = new DummySubjectQueryImpl();
        assertTrue(SAMLProcessorFactory.getProcessor(dummy) instanceof SAMLSubjectQueryProcessor);
    }

    @Test
    public void testGetProcessorFornull() {

        DummyLogoutRequestImpl dummy = new DummyLogoutRequestImpl();
        assertEquals(SAMLProcessorFactory.getProcessor(dummy), null);
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
