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

package org.wso2.carbon.identity.sso.saml.common;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO;

import java.util.Arrays;
import java.util.List;

import static org.testng.Assert.assertEquals;

/**
 * Test Class for the Util.
 */
public class UtilTest {

    private static int singleLogoutRetryCount = 5;
    private static long singleLogoutRetryInterval = 60000;

    @Test
    public void testGetSingleLogoutRetryCount() throws Exception {

        int singleLogoutRetryC = Util.getSingleLogoutRetryCount();
        assertEquals(singleLogoutRetryC, singleLogoutRetryCount);
    }

    @Test
    public void testSetSingleLogoutRetryCount() throws Exception {

        Util.setSingleLogoutRetryCount(6);
        assertEquals(Util.getSingleLogoutRetryCount(), 6);
        Util.setSingleLogoutRetryCount(singleLogoutRetryCount);
    }

    @Test
    public void testGetSingleLogoutRetryInterval() throws Exception {

        long singleLogoutRetryInt = Util.getSingleLogoutRetryInterval();
        assertEquals(singleLogoutRetryInt, singleLogoutRetryInterval);
    }

    @Test
    public void testSetSingleLogoutRetryInterval() throws Exception {

        Util.setSingleLogoutRetryInterval(70000);
        assertEquals(Util.getSingleLogoutRetryInterval(), 70000);
        Util.setSingleLogoutRetryInterval(singleLogoutRetryInterval);
    }

    @DataProvider(name = "provideHttpStatusCode")
    public Object[][] createData1() {
        return new Object[][]{
                {200, true},
                {302, false},
                {100, false},
                {500, false},
                {404, false},
                {202, true},
                {0, false},
        };
    }

    @Test(dataProvider = "provideHttpStatusCode")
    public void testIsHttpSuccessStatusCode(int status, boolean value) {

        assertEquals(Util.isHttpSuccessStatusCode(status), value);
    }

    @DataProvider(name = "provideServiceProvider")
    public Object[][] createServiceProvider() {

        SAMLSSOServiceProviderDTO SP1 = new SAMLSSOServiceProviderDTO();
        SP1.setIssuer("test1");
        SAMLSSOServiceProviderDTO SP2 = new SAMLSSOServiceProviderDTO();
        SP2.setIssuer("test2=");
        SAMLSSOServiceProviderDTO SP3 = new SAMLSSOServiceProviderDTO();
        SP3.setIssuer("test3");
        SAMLSSOServiceProviderDTO SP4 = new SAMLSSOServiceProviderDTO();
        SP4.setIssuer("test4");
        SAMLSSOServiceProviderDTO SP5 = new SAMLSSOServiceProviderDTO();
        SP5.setIssuer("test5=");
        SAMLSSOServiceProviderDTO SP6 = new SAMLSSOServiceProviderDTO();
        SP6.setIssuer("test6=");
        SAMLSSOServiceProviderDTO[] serviceProviderSet1 = new SAMLSSOServiceProviderDTO[]{SP1, SP2, SP3};
        SAMLSSOServiceProviderDTO[] serviceProviderSet1pattern = new SAMLSSOServiceProviderDTO[]{SP2};
        SAMLSSOServiceProviderDTO[] serviceProviderSet2 = new SAMLSSOServiceProviderDTO[]{SP1, SP2, SP3, SP4, SP5, SP6};
        SAMLSSOServiceProviderDTO[] serviceProviderSet2pattern = new SAMLSSOServiceProviderDTO[]{SP2, SP5, SP6};

        return new Object[][]{
                {serviceProviderSet1, serviceProviderSet1pattern},
                {serviceProviderSet2, serviceProviderSet2pattern}};
    }

    @Test(dataProvider = "provideServiceProvider")
    public void testDoPaging(SAMLSSOServiceProviderDTO[] serviceProviderSet,
                             SAMLSSOServiceProviderDTO[] serviceProviderSetpattern) throws Exception {

        SAMLSSOServiceProviderDTO[] returnServiceProviderSet = Util.doPaging(0, serviceProviderSet);
        Assert.assertTrue(assertSSOproviderArray(returnServiceProviderSet, serviceProviderSet));
    }

    @Test(dataProvider = "provideServiceProvider")
    public void testDoFilter(SAMLSSOServiceProviderDTO[] serviceProviderSet,
                             SAMLSSOServiceProviderDTO[] serviceProviderSetpattern) throws Exception {

        SAMLSSOServiceProviderDTO[] returnServiceProviderSet =
                Util.doFilter("^([A-Za-z0-9+/])*=$", serviceProviderSet);
        Assert.assertTrue(assertSSOproviderArray(returnServiceProviderSet, serviceProviderSetpattern));
    }

    public boolean assertSSOproviderArray(SAMLSSOServiceProviderDTO[] actual, SAMLSSOServiceProviderDTO[] expected) {

        SAMLSSOServiceProviderDTO[] expectedaArray = Arrays.copyOfRange(expected, 0, actual.length);
        return Arrays.deepEquals(actual, expectedaArray);
    }

}
