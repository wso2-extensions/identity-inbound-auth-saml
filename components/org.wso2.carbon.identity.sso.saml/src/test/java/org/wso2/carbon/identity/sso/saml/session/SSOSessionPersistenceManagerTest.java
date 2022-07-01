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

import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.sso.saml.TestConstants;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCache;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCacheKey;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOSessionIndexCache;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOSessionIndexCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOSessionIndexCacheKey;
import org.wso2.carbon.identity.sso.saml.common.SAMLSSOProviderConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({IdentityTenantUtil.class})
@PowerMockIgnore({"javax.xml.*", "org.xml.*", "org.w3c.dom.*"})
public class SSOSessionPersistenceManagerTest extends PowerMockTestCase {

    private SSOSessionPersistenceManager ssoSessionPersistenceManager;

    @BeforeMethod
    public void setUp() throws Exception {

        initMocks(this);
        ssoSessionPersistenceManager = new SSOSessionPersistenceManager();
        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).
                thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        when(IdentityTenantUtil.getTenantDomain(MultitenantConstants.SUPER_TENANT_ID)).
                thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        //remove the exsisting sessionIndex from cache
        SSOSessionPersistenceManager.removeSessionIndexFromCache("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @AfterMethod
    public void tearDown() throws Exception {

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
        SSOSessionPersistenceManager.addSessionIndexToCache("tokenid", "sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SAMLSSOSessionIndexCacheKey cacheKey = new SAMLSSOSessionIndexCacheKey("tokenid");
        SAMLSSOSessionIndexCacheEntry cacheEntry = SAMLSSOSessionIndexCache.getInstance().getValueFromCache(cacheKey,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertNotNull(cacheEntry);
        actualSessionIndex = cacheEntry.getSessionIndex();
        Assert.assertEquals(actualSessionIndex, "sessionIndex");
    }

    @Test
    public void testGetSessionInfoDataFromCache() throws Exception {

        SessionInfoData sessionInfoData = new SessionInfoData();
        SSOSessionPersistenceManager.addSessionInfoDataToCache("sessionId", sessionInfoData,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SessionInfoData actualSesssionInfoData = SSOSessionPersistenceManager.
                getSessionInfoDataFromCache("sessionId", MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(actualSesssionInfoData, sessionInfoData);
    }

    @Test
    public void testGetSessionIndexFromCache() throws Exception {

        String sessionIndex = "sessionIndex";
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", sessionIndex,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        String actualSessionIndex = SSOSessionPersistenceManager.getSessionIndexFromCache("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(actualSessionIndex, sessionIndex);
    }

    @Test
    public void testAddSessionInfoDataToCache() throws Exception {

        SessionInfoData sessionInfoData = new SessionInfoData();
        SSOSessionPersistenceManager.addSessionInfoDataToCache("sessionId", sessionInfoData,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey("sessionId");
        SAMLSSOParticipantCacheEntry cacheEntry = SAMLSSOParticipantCache.getInstance().
                getValueFromCache(cacheKey, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertNotNull(cacheEntry);
        SessionInfoData actualSessionInfoData = cacheEntry.getSessionInfoData();
        Assert.assertEquals(actualSessionInfoData, sessionInfoData);
    }

    @Test
    public void testRemoveSessionInfoDataFromCache() throws Exception {

        SSOSessionPersistenceManager.addSessionInfoDataToCache("sessionId", new SessionInfoData(),
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SSOSessionPersistenceManager.removeSessionInfoDataFromCache(null,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertNotNull(SSOSessionPersistenceManager.getSessionInfoDataFromCache("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME));
        SSOSessionPersistenceManager.removeSessionInfoDataFromCache("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertNull(SSOSessionPersistenceManager.getSessionInfoDataFromCache("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME));
    }

    @Test
    public void testRemoveSessionIndexFromCache() throws Exception {

        String sessionIndex;
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", "sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SSOSessionPersistenceManager.removeSessionIndexFromCache(null,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        sessionIndex = SSOSessionPersistenceManager.getSessionIndexFromCache("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertNotNull(sessionIndex);
        SSOSessionPersistenceManager.removeSessionIndexFromCache("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        sessionIndex = SSOSessionPersistenceManager.getSessionIndexFromCache("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertNull(sessionIndex);
    }

    @Test
    public void testGetSessionIndexFromTokenId() throws Exception {

        String sessionIndex = "sessionIndex";
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", sessionIndex,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        String actualSessionIndex = ssoSessionPersistenceManager.getSessionIndexFromTokenId("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(actualSessionIndex, sessionIndex);
    }

    @Test
    public void testRemoveTokenId() throws Exception {

        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", "sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        ssoSessionPersistenceManager.removeTokenId("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        String sessionIndex = ssoSessionPersistenceManager.getSessionIndexFromTokenId("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertNull(sessionIndex);
    }

    @Test
    public void testIsExistingTokenId() throws Exception {

        String sessionIndex = "sessionIndex";
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionIndex", sessionIndex,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(ssoSessionPersistenceManager.isExistingTokenId("sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), true);
        SSOSessionPersistenceManager.removeSessionIndexFromCache(sessionIndex,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(ssoSessionPersistenceManager.isExistingTokenId("sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), false);
    }

    @Test
    public void testGetSessionInfo() throws Exception {

        SessionInfoData sessionInfoData = new SessionInfoData();
        SSOSessionPersistenceManager.addSessionInfoDataToCache("sessionIndex", sessionInfoData,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SessionInfoData actualSessionInfoData = ssoSessionPersistenceManager.getSessionInfo("sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(actualSessionInfoData, sessionInfoData);
    }

    @Test
    public void testRemoveSession() throws Exception {

        SSOSessionPersistenceManager.addSessionInfoDataToCache("sessionIndex", new SessionInfoData(),
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        ssoSessionPersistenceManager.removeSession("sessionIndex");
        SessionInfoData sessionInfoData = SSOSessionPersistenceManager.getSessionInfoDataFromCache("sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertNull(sessionInfoData);
    }

    @Test
    public void testIsExistingSession() throws Exception {

        SessionInfoData sessionInfoData = new SessionInfoData();
        SSOSessionPersistenceManager.addSessionInfoDataToCache("sessionIndex", sessionInfoData,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(ssoSessionPersistenceManager.isExistingSession("sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), true);
        SSOSessionPersistenceManager.removeSessionInfoDataFromCache("sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(ssoSessionPersistenceManager.isExistingSession("sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), false);
    }

    @DataProvider(name = "testPersistSession1")
    public Object[][] values() {

        return new Object[][]{
                {null, null},
                {"sessionId", null},
                {"sessionId", "sessionIndex"}
        };
    }

    @Test(dataProvider = "testPersistSession1")
    public void testPersistSession1(String sessionId, String sessionIndex) throws Exception {

        ssoSessionPersistenceManager.persistSession(sessionId, sessionIndex,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        String actualValue = ssoSessionPersistenceManager.getSessionIndexFromTokenId(sessionId,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(actualValue, sessionIndex);
    }

    @Test
    public void testPersistSession() throws Exception {

        String issuer = "testUser";
        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setIssuer(issuer);
        SSOSessionPersistenceManager.addSessionInfoDataToCache("samlTokenId", new SessionInfoData(),
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        ssoSessionPersistenceManager.persistSession("samlTokenId", "subject", samlssoServiceProviderDO,
                "rpSessionId", issuer, TestConstants.ACS_URL, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SessionInfoData sessionInfoData = ssoSessionPersistenceManager.getSessionInfoDataFromCache("samlTokenId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        Assert.assertEquals(sessionInfoData.getSubject(issuer), "subject");
        Assert.assertFalse(sessionInfoData.getRPSessionsList().isEmpty());
        Assert.assertEquals(sessionInfoData.getServiceProviderList().get(issuer), samlssoServiceProviderDO);
        Assert.assertEquals(sessionInfoData.getServiceProviderList().get(issuer).getAssertionConsumerUrl(),
                TestConstants.ACS_URL);
    }

    public static void initializeData() throws IdentityException {

        String sessionIndex = "sessionIndex";
        String subject = "subject";
        String issuer = "issuer";

        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setIssuer(issuer);
        samlssoServiceProviderDO.setDoSingleLogout(true);
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", sessionIndex,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SSOSessionPersistenceManager.getPersistenceManager().persistSession(sessionIndex, subject,
                samlssoServiceProviderDO, null, issuer, null,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        SAMLSSOServiceProviderDO samlssoServiceProviderDO1 = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO1.setIssuer("issuer1");
        samlssoServiceProviderDO1.setDoSingleLogout(true);
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId1", "sessionIndex2",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SSOSessionPersistenceManager.getPersistenceManager().persistSession("sessionIndex2", subject,
                samlssoServiceProviderDO1, null, "issuer1", null,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        SAMLSSOServiceProviderDO samlssoServiceProviderDO2 = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO2.setIssuer("issuer2");
        samlssoServiceProviderDO2.setDoSingleLogout(false);
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId2", sessionIndex,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SSOSessionPersistenceManager.getPersistenceManager().persistSession(sessionIndex, subject,
                samlssoServiceProviderDO2, null, "issuer2", null,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        SAMLSSOServiceProviderDO samlssoServiceProviderDO3 = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO3.setIssuer("issuer3");
        samlssoServiceProviderDO3.setDoSingleLogout(true);
        samlssoServiceProviderDO3.setDoFrontChannelLogout(true);
        samlssoServiceProviderDO3.setFrontChannelLogoutBinding(SAMLSSOProviderConstants.HTTP_REDIRECT_BINDING);
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId3", "sessionIndex3",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SSOSessionPersistenceManager.getPersistenceManager().persistSession("sessionIndex3", subject,
                samlssoServiceProviderDO3, null, "issuer3", null,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @DataProvider(name = "testRemoveSession1")
    public Object[][] data() throws IdentityException {

        return new Object[][]{
                {null, null, null},
                {"sessionId", null, "sessionIndex",},
                {"sessionId", "issuer", "sessionIndex"},
                {"sessionId2", "issuer2", "sessionIndex"},
                {"sessionId1", "issuer1", null},
                {"sessionId1", null, null},
                {"sessionId3", "issuer3", "sessionIndex3"}
        };
    }

    @Test(dataProvider = "testRemoveSession1")
    public void testRemoveSession1(String sessionId, String issuer, String expected) throws Exception {

        initializeData();
        SSOSessionPersistenceManager.removeSession(sessionId, issuer, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Assert.assertEquals(SSOSessionPersistenceManager.getSessionIndexFromCache(sessionId,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), expected);
    }

    @Test
    public void testRemoveSession2() throws Exception {

        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setIssuer("issuer");
        samlssoServiceProviderDO.setDoSingleLogout(true);
        SSOSessionPersistenceManager.addSessionIndexToCache("sessionId", "sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SSOSessionPersistenceManager.getPersistenceManager().persistSession("sessionIndex", "sub",
                samlssoServiceProviderDO, null, "issuer", null,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SSOSessionPersistenceManager.removeSession("sessionId", "issuer",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

}
