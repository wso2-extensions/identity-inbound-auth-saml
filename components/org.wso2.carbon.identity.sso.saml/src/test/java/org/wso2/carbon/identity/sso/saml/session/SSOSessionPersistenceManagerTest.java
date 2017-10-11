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

import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCache;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCacheKey;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOSessionIndexCache;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOSessionIndexCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOSessionIndexCacheKey;

import java.nio.file.Paths;

import static org.mockito.MockitoAnnotations.initMocks;

public class SSOSessionPersistenceManagerTest extends PowerMockTestCase {

    private SSOSessionPersistenceManager ssoSessionPersistenceManager;

    @BeforeMethod
    public void setUp() throws Exception {

        initMocks(this);
        ssoSessionPersistenceManager = new SSOSessionPersistenceManager();
        initPrivilegedCarbonContext("carbon.super", -1234, "testUser");
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    public static void initPrivilegedCarbonContext(String tenantDomain, int tenantID, String userName) throws Exception {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(userName);
    }

    @Test
    public void testGetPersistenceManager() throws Exception {

        SSOSessionPersistenceManager persistenceManager = SSOSessionPersistenceManager.getPersistenceManager();
        Assert.assertNotNull(persistenceManager);

        SSOSessionPersistenceManager anotherPersistenceManager = SSOSessionPersistenceManager.getPersistenceManager();
        Assert.assertNotNull(anotherPersistenceManager);

        Assert.assertEquals(persistenceManager, anotherPersistenceManager);
    }

    @Test
    public void testAddSessionIndexToCache() throws Exception {

        String actualSessionIndex = null;

        SSOSessionPersistenceManager.addSessionIndexToCache("tokenid", "456");

        SAMLSSOSessionIndexCacheKey cacheKey = new SAMLSSOSessionIndexCacheKey("tokenid");
        SAMLSSOSessionIndexCacheEntry cacheEntry = SAMLSSOSessionIndexCache.getInstance().getValueFromCache(cacheKey);

        if (cacheEntry != null) {
            actualSessionIndex = cacheEntry.getSessionIndex();
        }
        Assert.assertEquals(actualSessionIndex, "456");
    }

    @Test
    public void testGetSessionInfoDataFromCache() throws Exception {

        SessionInfoData sessionInfoData = new SessionInfoData();
        SSOSessionPersistenceManager.addSessionInfoDataToCache("123", sessionInfoData);

        SessionInfoData actualSesssionInfoData = SSOSessionPersistenceManager.getSessionInfoDataFromCache("123");

        Assert.assertEquals(actualSesssionInfoData, sessionInfoData);
    }

    @Test
    public void testGetSessionIndexFromCache() throws Exception {

        String sessionIndex = "sessionIndex";
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", sessionIndex);

        String actualSessionIndex = SSOSessionPersistenceManager.getSessionIndexFromCache("sessionId");

        Assert.assertEquals(actualSessionIndex, sessionIndex);
    }

    @Test
    public void testAddSessionInfoDataToCache() throws Exception {

        SessionInfoData actualSessionInfoData = null;
        SessionInfoData sessionInfoData = new SessionInfoData();

        SSOSessionPersistenceManager.addSessionInfoDataToCache("123", sessionInfoData);

        SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey("123");
        SAMLSSOParticipantCacheEntry cacheEntry = SAMLSSOParticipantCache.getInstance().getValueFromCache(cacheKey);

        if (cacheEntry != null) {
            actualSessionInfoData = cacheEntry.getSessionInfoData();
        }
        Assert.assertEquals(actualSessionInfoData, sessionInfoData);
    }

    @Test
    public void testRemoveSessionInfoDataFromCache() throws Exception {

        SSOSessionPersistenceManager.addSessionInfoDataToCache("123", new SessionInfoData());

        SSOSessionPersistenceManager.removeSessionInfoDataFromCache(null);
        Assert.assertNotNull(SSOSessionPersistenceManager.getSessionInfoDataFromCache("123"));

        SSOSessionPersistenceManager.removeSessionInfoDataFromCache("123");
        Assert.assertNull(SSOSessionPersistenceManager.getSessionInfoDataFromCache("123"));
    }

    @Test
    public void testRemoveSessionIndexFromCache() throws Exception {

        String sessionIndex;
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", "456");

        SSOSessionPersistenceManager.removeSessionIndexFromCache(null);
        sessionIndex = SSOSessionPersistenceManager.getSessionIndexFromCache("sessionId");
        Assert.assertNotNull(sessionIndex);

        SSOSessionPersistenceManager.removeSessionIndexFromCache("sessionId");
        sessionIndex = SSOSessionPersistenceManager.getSessionIndexFromCache("sessionId");
        Assert.assertNull(sessionIndex);
    }

    @Test
    public void testGetSessionIndexFromTokenId() throws Exception {

        String sessionIndex = "sessionIndex";
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", sessionIndex);

        String actualSessionIndex = ssoSessionPersistenceManager.getSessionIndexFromTokenId("sessionId");

        Assert.assertEquals(actualSessionIndex, sessionIndex);
    }

    @Test
    public void testRemoveTokenId() throws Exception {

        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", "456");

        ssoSessionPersistenceManager.removeTokenId("sessionId");

        String sessionIndex = ssoSessionPersistenceManager.getSessionIndexFromTokenId("sessionId");
        Assert.assertNull(sessionIndex);
    }

    @Test
    public void testIsExistingTokenId() throws Exception {

        String sessionIndex = "sessionIndex";

        SSOSessionPersistenceManager.addSessionIndexToCache("sessionIndex", sessionIndex);
        Assert.assertEquals(ssoSessionPersistenceManager.isExistingTokenId("sessionIndex"), true);

        SSOSessionPersistenceManager.removeSessionIndexFromCache(sessionIndex);
        Assert.assertEquals(ssoSessionPersistenceManager.isExistingTokenId("sessionIndex"), false);
    }

    @Test
    public void testGetSessionInfo() throws Exception {

        SessionInfoData sessionInfoData = new SessionInfoData();
        SSOSessionPersistenceManager.addSessionInfoDataToCache("sessionIndex", sessionInfoData);

        SessionInfoData actualSessionInfoData = ssoSessionPersistenceManager.getSessionInfo("sessionIndex");
        Assert.assertEquals(actualSessionInfoData, sessionInfoData);
    }

    @Test
    public void testRemoveSession() throws Exception {

        SSOSessionPersistenceManager.addSessionInfoDataToCache("sessionIndex", new SessionInfoData());

        ssoSessionPersistenceManager.removeSession("sessionIndex");
        SessionInfoData sessionInfoData = SSOSessionPersistenceManager.getSessionInfoDataFromCache("sessionIndex");

        Assert.assertNull(sessionInfoData);
    }

    @Test
    public void testIsExistingSession() throws Exception {

        SessionInfoData sessionInfoData = new SessionInfoData();

        SSOSessionPersistenceManager.addSessionInfoDataToCache("sessionIndex", sessionInfoData);
        Assert.assertEquals(ssoSessionPersistenceManager.isExistingSession("sessionIndex"), true);

        SSOSessionPersistenceManager.removeSessionInfoDataFromCache("sessionIndex");
        Assert.assertEquals(ssoSessionPersistenceManager.isExistingSession("sessionIndex"), false);
    }

    @DataProvider(name = "testPersistSession1")
    public Object[][] values() {

        SSOSessionPersistenceManager.removeSessionIndexFromCache("sessionId");

        return new Object[][]{
                {null, null},
                {"sessionId", null},
                {"sessionId", "sessionIndex"}
        };
    }

    @Test(dataProvider = "testPersistSession1")
    public void testPersistSession1(String sessionId, String sessionIndex) throws Exception {

        ssoSessionPersistenceManager.persistSession(sessionId, sessionIndex);
        String actualValue = ssoSessionPersistenceManager.getSessionIndexFromTokenId(sessionId);

        Assert.assertEquals(actualValue, sessionIndex);
    }

    @Test
    public void testPersistSession() throws Exception {

        String issuer = "testUser";
        String assertionConsumerUrl = "localhost.com:8080/avis.com/home.jsp";
        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setIssuer(issuer);
        SSOSessionPersistenceManager.addSessionInfoDataToCache("samlTokenId", new SessionInfoData());
        ssoSessionPersistenceManager.persistSession("samlTokenId", "subject", samlssoServiceProviderDO, "rpSessionId", issuer, assertionConsumerUrl);

        SessionInfoData sessionInfoData = ssoSessionPersistenceManager.getSessionInfoDataFromCache("samlTokenId");
        Assert.assertEquals(sessionInfoData.getSubject(issuer), "subject");
        Assert.assertFalse(sessionInfoData.getRPSessionsList().isEmpty());
        Assert.assertEquals(sessionInfoData.getServiceProviderList().get(issuer), samlssoServiceProviderDO);
        Assert.assertEquals(sessionInfoData.getServiceProviderList().get(issuer).getAssertionConsumerUrl(), assertionConsumerUrl);
    }

    public static void initializeData() throws IdentityException {

        String sessionIndex = "sessionIndex";
        String subject = "subject";
        String issuer = "issuer";

        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setIssuer(issuer);
        samlssoServiceProviderDO.setDoSingleLogout(true);
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", sessionIndex);
        SSOSessionPersistenceManager.getPersistenceManager().persistSession(sessionIndex, subject, samlssoServiceProviderDO, null, issuer, null);
//
        SAMLSSOServiceProviderDO samlssoServiceProviderDO1 = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO1.setIssuer("issuer1");
        samlssoServiceProviderDO1.setDoSingleLogout(true);
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId1", "sessionIndex2");
        SSOSessionPersistenceManager.getPersistenceManager().persistSession("sessionIndex2", subject, samlssoServiceProviderDO1, null, "issuer1", null);

        SAMLSSOServiceProviderDO samlssoServiceProviderDO2 = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO2.setIssuer("issuer2");
        samlssoServiceProviderDO2.setDoSingleLogout(false);
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId2", sessionIndex);
        SSOSessionPersistenceManager.getPersistenceManager().persistSession(sessionIndex, subject, samlssoServiceProviderDO2, null, "issuer2", null);

    }

    @DataProvider(name = "testRemoveSession1")
    public Object[][] data() throws IdentityException {

        return new Object[][]{
                {null, null, null},
                {"sessionId", null, "sessionIndex",},
                {"sessionId", "issuer", "sessionIndex"},
                {"sessionId2", "issuer2", "sessionIndex"},
                {"sessionId1", "issuer1", null}
        };
    }

    @Test(dataProvider = "testRemoveSession1")
    public void testRemoveSession1(String sessionId, String issuer, String expected) throws Exception {

        initializeData();
        SSOSessionPersistenceManager.removeSession(sessionId, issuer);
        Assert.assertEquals(SSOSessionPersistenceManager.getSessionIndexFromCache(sessionId), expected);
    }

    @Test
    public void testRemoveSession2() throws Exception {

        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setIssuer("issuer");
        samlssoServiceProviderDO.setDoSingleLogout(true);
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", "sessionIndex");
        SSOSessionPersistenceManager.getPersistenceManager().persistSession("sessionIndex", "sub", samlssoServiceProviderDO, null, "issuer", null);
        SSOSessionPersistenceManager.removeSession("sessionId", "issuer");
    }

}