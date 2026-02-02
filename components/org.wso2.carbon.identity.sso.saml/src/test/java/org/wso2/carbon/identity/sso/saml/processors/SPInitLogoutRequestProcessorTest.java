/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
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

package org.wso2.carbon.identity.sso.saml.processors;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.session.SessionInfoData;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

/**
 * Unit tests for SPInitLogoutRequestProcessor.
 */
public class SPInitLogoutRequestProcessorTest {

    private static final String TEST_ISSUER = "test-issuer";
    private static final String NON_EXISTENT_ISSUER = "non-existent-issuer";

    private SPInitLogoutRequestProcessor spInitLogoutRequestProcessor;
    private Method validateIssuerWithSessionMethod;

    @BeforeMethod
    public void setUp() throws Exception {

        spInitLogoutRequestProcessor = new SPInitLogoutRequestProcessor();
        validateIssuerWithSessionMethod = SPInitLogoutRequestProcessor.class.getDeclaredMethod(
                "validateIssuerWithSession", String.class, SessionInfoData.class);
        validateIssuerWithSessionMethod.setAccessible(true);
    }

    @DataProvider(name = "validIssuerDataProvider")
    public Object[] validIssuerDataProvider() {

        return new Object[]{
                TEST_ISSUER,
                "issuer-with-special-chars@domain.com",
                "issuer_with_underscore"
        };
    }

    @Test(dataProvider = "validIssuerDataProvider",
            description = "Test validateIssuerWithSession with various valid issuers")
    public void testValidateIssuerWithSessionWhenServiceProviderExists(String issuer) throws Exception {

        SessionInfoData sessionInfoData = createSessionInfoDataWithServiceProvider();

        // Should not throw any exception when issuer exists in session
        validateIssuerWithSessionMethod.invoke(spInitLogoutRequestProcessor, TEST_ISSUER, sessionInfoData);
    }

    @Test(description = "Test validateIssuerWithSession when service provider does not exist in session")
    public void testValidateIssuerWithSessionWhenServiceProviderDoesNotExist() throws Exception {

        SessionInfoData sessionInfoData = createSessionInfoDataWithServiceProvider();

        try {
            validateIssuerWithSessionMethod.invoke(spInitLogoutRequestProcessor, NON_EXISTENT_ISSUER, sessionInfoData);
            fail("Expected IdentityException was not thrown");
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            assertNotNull(cause, "Exception cause should not be null");
            assertEquals(cause.getClass(), IdentityException.class, "Expected IdentityException");
            assertEquals(cause.getMessage(), "Service provider :" + NON_EXISTENT_ISSUER +
                    " does not exist in session info data.");
        }
    }

    /**
     * Helper method to create SessionInfoData with a service provider.
     *
     * @return SessionInfoData containing the service provider.
     */
    private SessionInfoData createSessionInfoDataWithServiceProvider() {

        SessionInfoData sessionInfoData = new SessionInfoData();
        SAMLSSOServiceProviderDO serviceProviderDO = new SAMLSSOServiceProviderDO();
        serviceProviderDO.setIssuer(SPInitLogoutRequestProcessorTest.TEST_ISSUER);
        sessionInfoData.addServiceProvider(SPInitLogoutRequestProcessorTest.TEST_ISSUER, serviceProviderDO, null);
        return sessionInfoData;
    }
}
