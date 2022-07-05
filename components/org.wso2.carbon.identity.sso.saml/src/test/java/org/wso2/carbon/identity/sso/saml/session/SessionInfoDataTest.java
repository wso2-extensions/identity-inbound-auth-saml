/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml.session;

import org.mockito.Mock;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;

import static org.mockito.MockitoAnnotations.initMocks;

public class SessionInfoDataTest {

    @Mock
    private SessionInfoData sessionInfoData;

    @Mock
    private SAMLSSOServiceProviderDO samlssoServiceProviderDO;

    @BeforeMethod
    public void setUp() throws Exception {

        sessionInfoData = new SessionInfoData();
        samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        sessionInfoData.addServiceProvider("testUser", samlssoServiceProviderDO, null);
        sessionInfoData.addServiceProvider("testUser1", samlssoServiceProviderDO, "rpSessionId");
        sessionInfoData.setSubject("testUser", "subject");
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test
    public void testGetServiceProviderList() throws Exception {

        Assert.assertEquals(sessionInfoData.getServiceProviderList().get("testUser"), samlssoServiceProviderDO);
    }

    @Test
    public void testAddServiceProvider() throws Exception {

        Assert.assertEquals(sessionInfoData.getServiceProviderList().get("testUser"), samlssoServiceProviderDO);
        Assert.assertEquals(sessionInfoData.getServiceProviderList().get("testUser1"), samlssoServiceProviderDO);
    }

    @Test
    public void testRemoveServiceProvider() throws Exception {

        sessionInfoData.removeServiceProvider("testUser1");
        Assert.assertFalse(sessionInfoData.getServiceProviderList().containsKey("testUser1"));
        Assert.assertFalse(sessionInfoData.getRPSessionsList().containsKey("testUser1"));
    }

    @Test
    public void testGetRPSessionsList() throws Exception {

        Assert.assertEquals(sessionInfoData.getRPSessionsList().get("testUser1"), "rpSessionId");
    }

    @Test
    public void testSetSubject() throws Exception {

        String actualSubject = sessionInfoData.getSubject("testUser");
        Assert.assertEquals(actualSubject, "subject");
    }

}
