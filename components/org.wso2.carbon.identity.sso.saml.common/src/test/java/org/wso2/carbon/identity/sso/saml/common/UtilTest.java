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

package org.wso2.carbon.identity.sso.saml.common;

import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO;

import static org.testng.Assert.assertEquals;

public class UtilTest extends PowerMockTestCase {

    @DataProvider
    public Object[][] getSingleLogoutTryCounts() {
        return new Object[][]{
                {null, 5, "Default value should equal to 5"},
                {1, 1, "Retry count set to 1"},
                {10, 10, "Retry count set to 10"},
        };
    }

    @Test(dataProvider = "getSingleLogoutTryCounts")
    public void testGetSingleLogoutRetryCount(Integer retryCount, int expected, String message) throws Exception {
        if (retryCount != null) {
            Util.setSingleLogoutRetryCount(retryCount);
        }
        assertEquals(Util.getSingleLogoutRetryCount(), expected, message);
    }

    @DataProvider
    public Object[][] getSingleLogoutTryIntervals() {
        return new Object[][]{
                {null, 60000, "Default value should equal to 60000"},
                {1000, 1000, "Retry count set to 1000"},
                {100000, 100000, "Retry count set to 100000"},
        };
    }

    @Test(dataProvider = "getSingleLogoutTryIntervals")
    public void testGetSingleLogoutRetryInterval(Integer retryInterval, int expected, String message) throws Exception {
        if (retryInterval != null) {
            Util.setSingleLogoutRetryInterval(retryInterval);
        }
        assertEquals(Util.getSingleLogoutRetryInterval(), expected, message);
    }

    @DataProvider
    public Object[][] getHTTPStatusCodes() {
        return new Object[][]{
                {101, false, "101 is not a success code"}, {200, true, "200 is a success code"},
                {201, true, "201 is a success code"}, {202, true, "202 is a success code"},
                {203, true, "203 is a success code"}, {204, true, "204 is a success code"},
                {205, true, "205 is a success code"}, {206, true, "206 is a success code"},
                {207, true, "207 is a success code"}, {208, true, "208 is a success code"},
                {226, true, "209 is a success code"}, {300, false, "300 is not a success code"},
                {301, false, "301 is not a success code"}, {403, false, "403 is not a success code"},
                {504, false, "504 is not a success code"},
        };
    }

    @Test(dataProvider = "getHTTPStatusCodes")
    public void testIsHttpSuccessStatusCode(int status, boolean expected, String message) throws Exception {
        assertEquals(Util.isHttpSuccessStatusCode(status), expected, message);
    }

    @DataProvider
    public Object[][] getServiceProviders() {
        SAMLSSOServiceProviderDTO[] spArray1 = getServiceProviderArray(2);
        SAMLSSOServiceProviderDTO[] spArray2 = getServiceProviderArray(5);
        SAMLSSOServiceProviderDTO[] spArray3 = getServiceProviderArray(8);
        return new Object[][]{
                {spArray1, 0, 2, 2}, {spArray2, 0, 5, 5}, {spArray3, 0, 5, 5},
        };
    }

    @Test(dataProvider = "getServiceProviders")
    public void testDoPaging(Object serviceProviders, int pageNumber, int pageLength, int finalSPIssuer) throws
            Exception {
        SAMLSSOServiceProviderDTO[] resultServiceProviderDTOs = Util.doPaging(pageNumber,
                (SAMLSSOServiceProviderDTO[]) serviceProviders);
        assertEquals(resultServiceProviderDTOs.length, pageLength, "Result set of service providers does not have" +
                " expected length");
        assertEquals(Integer.parseInt((resultServiceProviderDTOs[resultServiceProviderDTOs.length - 1]).getIssuer()),
                finalSPIssuer, "Final issuer did not match");
    }

    private SAMLSSOServiceProviderDTO[] getServiceProviderArray(int arraySize) {
        SAMLSSOServiceProviderDTO[] samlssoServiceProviderDTOArray = new SAMLSSOServiceProviderDTO[arraySize];
        for (int i = 1; i <= arraySize; i++) {
            SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
            samlssoServiceProviderDTO.setIssuer(Integer.toString(i));
            samlssoServiceProviderDTOArray[i - 1] = samlssoServiceProviderDTO;
        }
        return samlssoServiceProviderDTOArray;
    }
}