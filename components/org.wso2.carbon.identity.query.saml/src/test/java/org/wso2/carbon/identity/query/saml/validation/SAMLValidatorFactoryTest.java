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

import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.testng.Assert;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.AssertionIDRequest;
import org.opensaml.saml.saml2.core.AttributeQuery;
import org.opensaml.saml.saml2.core.AuthnQuery;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.SubjectQuery;
import org.opensaml.saml.saml2.core.impl.AuthzDecisionQueryImpl;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;

import java.util.ArrayList;
import java.util.List;

/**
 * Test Class for the SAMLValidatorFactory.
 */
public class SAMLValidatorFactoryTest {

    List<InvalidItemDTO> testInvalidItems = new ArrayList<>();
    RequestAbstractType testrequest;
    SAMLQueryValidator testSamlQueryValidator;
    InvalidItemDTO testInvalidItemDTO = new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_MESSAGE_TYPE,
            SAMLQueryRequestConstants.ValidationMessage.VAL_MESSAGE_TYPE_ERROR);

    @Test
    public void testGetValidatorAssertionIDRequest() {

        testrequest = Mockito.mock(AssertionIDRequest.class, Mockito.CALLS_REAL_METHODS);
        testSamlQueryValidator = SAMLValidatorFactory.getValidator(testInvalidItems, testrequest);
        Assert.assertTrue(testSamlQueryValidator instanceof SAMLIDRequestValidator);
    }

    @Test
    public void testGetValidatorAttributeQuery() {

        testrequest = Mockito.mock(AttributeQuery.class, Mockito.CALLS_REAL_METHODS);
        testSamlQueryValidator = SAMLValidatorFactory.getValidator(testInvalidItems, testrequest);
        Assert.assertTrue(testSamlQueryValidator instanceof SAMLAttributeQueryValidator);
    }

    @Test
    public void testGetValidatorAuthnQuery() {

        testrequest = Mockito.mock(AuthnQuery.class, Mockito.CALLS_REAL_METHODS);
        testSamlQueryValidator = SAMLValidatorFactory.getValidator(testInvalidItems, testrequest);
        Assert.assertTrue(testSamlQueryValidator instanceof SAMLAuthQueryValidator);
    }

    @Test
    public void testGetValidatorAuthzDecisionQueryImpl() {

        testrequest = Mockito.mock(AuthzDecisionQueryImpl.class, Mockito.CALLS_REAL_METHODS);
        testSamlQueryValidator = SAMLValidatorFactory.getValidator(testInvalidItems, testrequest);
        Assert.assertTrue(testSamlQueryValidator instanceof SAMLAuthzDecisionValidator);
    }

    @Test
    public void testGetValidatorSubjectQuery() {

        testrequest = Mockito.mock(SubjectQuery.class, Mockito.CALLS_REAL_METHODS);
        testSamlQueryValidator = SAMLValidatorFactory.getValidator(testInvalidItems, testrequest);
        Assert.assertTrue(testSamlQueryValidator instanceof SAMLSubjectQueryValidator);
    }

    @Test
    public void testGetValidatorOther() {

        testrequest = Mockito.mock(RequestAbstractType.class, Mockito.CALLS_REAL_METHODS);
        testSamlQueryValidator = SAMLValidatorFactory.getValidator(testInvalidItems, testrequest);
        Assert.assertTrue(testInvalidItems.get(0).getMessage().equals(testInvalidItemDTO.getMessage()));
        Assert.assertTrue(testInvalidItems.get(0).getValidationType().equals(testInvalidItemDTO.getValidationType()));
        Assert.assertEquals(null, testSamlQueryValidator);
    }

}
