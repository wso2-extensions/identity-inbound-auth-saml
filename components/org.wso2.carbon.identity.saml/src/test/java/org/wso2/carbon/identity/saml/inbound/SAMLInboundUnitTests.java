/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.saml.inbound;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponse;
import org.wso2.carbon.identity.mgt.IdentityStore;
import org.wso2.carbon.identity.mgt.RealmService;
import org.wso2.carbon.identity.mgt.exception.DomainException;
import org.wso2.carbon.identity.mgt.impl.Domain;
import org.wso2.carbon.identity.mgt.impl.internal.IdentityMgtDataHolder;
import org.wso2.carbon.identity.saml.exception.SAMLClientException;
import org.wso2.carbon.identity.saml.request.SAMLRequestBuilderFactory;
import org.wso2.carbon.identity.saml.response.SAMLErrorResponse;
import org.wso2.carbon.identity.saml.response.SAMLResponseBuilderFactory;

import javax.ws.rs.core.Response;

/**
 * Identity Store Tests.
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
        SAMLRequestBuilderFactory factory = new SAMLRequestBuilderFactory();
        Assert.assertEquals(factory.getName(), "SAMLRequestBuilderFactory");
        SAMLClientException exception = SAMLClientException.error("ErrorCode", "ErrorMessage",
                "ExceptionMessage", "http://8080/gateway?notificationendpoint");

        Response.ResponseBuilder responseBuilder = factory.handleException(exception);
        Response response = responseBuilder.build();
        //  We cannot access content in ms4j response. or builder. Hence there is no way of asserting content
        Assert.assertNotNull(response);
    }

    @Test
    public void testSAMLResponseBuilderFactory() {
        SAMLResponseBuilderFactory builderFactory = new SAMLResponseBuilderFactory();
        GatewayResponse.GatewayResponseBuilder gatewayResponseBuilder = new GatewayResponse.GatewayResponseBuilder
                (null);
        SAMLErrorResponse.SAMLErrorResponseBuilder samlErrorResponseBuilder = new SAMLErrorResponse
                .SAMLErrorResponseBuilder(null);
        samlErrorResponseBuilder.setErrorResponse("Error Response");
        samlErrorResponseBuilder.setAcsUrl("http://localhost:8080/acs");
        samlErrorResponseBuilder.setMessageLog("MessageLog");
        samlErrorResponseBuilder.setStatus("Status");

        SAMLErrorResponse samlErrorResponse = new SAMLErrorResponse(samlErrorResponseBuilder);
        Response.ResponseBuilder responseBuilder = builderFactory.createBuilder(samlErrorResponse);
        Response response = responseBuilder.build();
        //  We cannot access content in ms4j response. or builder. Hence there is no way of asserting content
        Assert.assertNotNull(response);
    }
}

