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

import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.impl.IssuerImpl;
import org.opensaml.saml.saml2.core.impl.SubjectQueryImpl;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.Test;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.AssertJUnit.assertEquals;

/**
 * Test Class for the SAMLSubjectQueryProcessor.
 */
@PrepareForTest({MultitenantUtils.class})
public class SAMLSubjectQueryProcessorTest extends PowerMockTestCase {

    SAMLSubjectQueryProcessor testclass = new SAMLSubjectQueryProcessor();

    @Test
    public void testGetIssuer() {

        DummyIssuer issuer = new DummyIssuer();
        issuer.setValue("test");
        DummySubjectQueryImpl dumRequest = new DummySubjectQueryImpl();
        dumRequest.setIssuer(issuer);
        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantAwareUsername(anyString())).thenReturn("test");
        assertEquals(testclass.getIssuer(dumRequest), "test");
    }

    @Test
    public void testGetTenantDomain() {

        DummyIssuer issuer = new DummyIssuer();
        issuer.setValue("test");
        DummySubjectQueryImpl dumRequest = new DummySubjectQueryImpl();
        dumRequest.setIssuer(issuer);
        mockStatic(MultitenantUtils.class);
        when(MultitenantUtils.getTenantDomain(anyString())).thenReturn("test");
        assertEquals(testclass.getTenantDomain(dumRequest), "test");
    }

    class DummySubjectQueryImpl extends SubjectQueryImpl {

        protected DummySubjectQueryImpl() {
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

    class DummyIssuer extends IssuerImpl {

        protected DummyIssuer() {
            super("testNSU", "testELN", "testNSP");
        }

    }

}