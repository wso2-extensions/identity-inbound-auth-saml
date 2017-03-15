/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


package org.wso2.carbon.identity.saml.inbound;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.mgt.IdentityStore;
import org.wso2.carbon.identity.mgt.RealmService;
import org.wso2.carbon.identity.mgt.exception.DomainException;
import org.wso2.carbon.identity.mgt.impl.Domain;
import org.wso2.carbon.identity.mgt.impl.internal.IdentityMgtDataHolder;

/**
 * SAML inbound unit tests.
 */
@PrepareForTest()
public class SAMLInboundUnitTests {

    @Mock
    private RealmService realmService;

    //    @Mock
    //    private AuthorizationStore authorizationStore;

    @Mock
    private IdentityMgtDataHolder identityMgtDataHolder;

    @Mock
    private Domain domain;

    private IdentityStore identityStore;

    @BeforeClass
    public void initClass() {

        MockitoAnnotations.initMocks(this);
    }

    @BeforeMethod
    public void initMethod() throws DomainException {

    }

    @AfterMethod
    public void resetMocks() {

        Mockito.reset(realmService);
        //      Mockito.reset(authorizationStore);
        Mockito.reset(identityMgtDataHolder);
    }

    @Test
    public void testHandleException() {
//        SAML2SSORequestBuilderFactory factory = new SAML2SSORequestBuilderFactory();
//        Assert.assertEquals(factory.getName(), "SAML2SSORequestBuilderFactory");
//        SAML2SSORequestValidationException exception = new SAML2SSORequestValidationException("ErrorCode", "ErrorMessage");
//        exception.setAcsUrl("http://8080/gateway?notificationendpoint");
//
//        Response.ResponseBuilder responseBuilder = factory.handleException(exception);
//        Response response = responseBuilder.build();
//        //  We cannot access content in mss4j response. or builder. Hence there is no way of asserting content
//        Assert.assertNotNull(response);
    }
}

