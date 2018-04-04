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

package org.wso2.carbon.identity.sso.saml;

import org.mockito.Mock;
import org.opensaml.DefaultBootstrap;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.session.SessionInfoData;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.security.keystore.KeyStoreAdmin;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.HashMap;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;


/**
 * Unit Tests for SAMLLogoutHandler.
 */
@PrepareForTest({HttpServletRequest.class, IdentityProviderManager.class, DefaultBootstrap.class,
        SSLContext.class, IdentityProvider.class, IdentityUtil.class, ServerConfiguration.class,
        KeyStoreManager.class, Class.class, KeyStoreAdmin.class, KeyStoreUtil.class})
public class SAMLLogoutHandlerTest extends PowerMockTestCase {

    private static String SESSION_INDEX = "theSessionIndex";
    private static String SESSION_TOKEN_ID = "samlssoTokenId";
    @Mock
    SSLContext sslContext;
    @Mock
    SecureRandom secureRandom;
    @Mock
    ServerConfiguration serverConfiguration;
    @Mock
    IdentityProviderManager identityProviderManager;
    @Mock
    IdentityProvider identityProvider;
    @Mock
    KeyStoreManager keyStoreManager;
    @Mock
    RegistryService registryService;
    @Mock
    UserRegistry registry;
    @Mock
    Collection collection;

    private KeyManager[] keyManagers = {new KeyManager() {
    }};
    private TrustManager[] trustManagers = {new TrustManager() {
    }};
    private FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = {};
    private String[] collectionString = {};

    @BeforeMethod
    public void setUp() throws Exception {

        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SAMLSSOServiceProviderDO serviceProviderDOOne = new SAMLSSOServiceProviderDO();
        serviceProviderDOOne.setIssuer("issuerOne");
        SAMLSSOServiceProviderDO serviceProviderDOTwo = new SAMLSSOServiceProviderDO();
        serviceProviderDOTwo.setIssuer("issuerTwo");

        SessionInfoData sessionInfoData = new SessionInfoData();
        sessionInfoData.addServiceProvider("issuerOne", serviceProviderDOOne, null);
        sessionInfoData.addServiceProvider("issuerTwo", serviceProviderDOTwo, null);

        SSOSessionPersistenceManager.addSessionIndexToCache(SESSION_TOKEN_ID, SESSION_INDEX);
        SSOSessionPersistenceManager.addSessionInfoDataToCache(SESSION_INDEX, sessionInfoData);


        // creating mocks
        mockStatic(SSLContext.class);
        when(SSLContext.getInstance(anyString())).thenReturn(sslContext);
        doNothing().when(sslContext).init(keyManagers, trustManagers, secureRandom);

        spy(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(anyString())).thenReturn(identityProvider);
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(federatedAuthenticatorConfigs);

        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(IdentityConstants.ServerConfig.ENTITY_ID)).thenReturn("IDPOne");
        when(IdentityUtil.getProperty(SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME))
                .thenReturn("org.wso2.carbon.identity.sso.saml.builders.signature.DefaultSSOSigner");

        mockStatic(ServerConfiguration.class);
        when(ServerConfiguration.getInstance()).thenReturn(serverConfiguration);
        when(serverConfiguration.getFirstProperty("Security.KeyStore.KeyAlias")).thenReturn("wso2carbon");
        when(serverConfiguration.getFirstProperty("Security.KeyStore.KeyPassword")).thenReturn("wso2carbon");
        when(serverConfiguration.getFirstProperty("Security.KeyStore.Location")).thenReturn("");
        when(serverConfiguration.getFirstProperty("Security.KeyStore.Type")).thenReturn("");


        mockStatic(KeyStoreUtil.class);
        when(KeyStoreUtil.getKeyStoreFileName(anyString())).thenReturn("wso2carbon");
        when(KeyStoreUtil.isPrimaryStore(anyString())).thenReturn(true);

        KeyStore keyStore = TestUtils.
                loadKeyStoreFromFileSystem(TestUtils.getFilePath("wso2carbon.jks"), "wso2carbon", "JKS");

        SAMLSSOUtil.setRegistryService(registryService);
        when(registryService.getGovernanceSystemRegistry()).thenReturn(registry);
        when(registry.resourceExists(anyString())).thenReturn(true);
        when(registry.get(anyString())).thenReturn(collection);
        when(collection.getChildren()).thenReturn(collectionString);

        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID)).thenReturn(keyStoreManager);
        when(keyStoreManager.getPrimaryKeyStore()).thenReturn(keyStore);

    }

    @Test
    public void testHandleEvent() throws Exception {

        Event eventOne = setupEvent(IdentityEventConstants.EventName.SESSION_TERMINATE.name(), "issuerOne");
        SAMLLogoutHandler samlLogoutHandler = new SAMLLogoutHandler();
        samlLogoutHandler.handleEvent(eventOne);
        SessionInfoData sessionInfoData = SSOSessionPersistenceManager.getSessionInfoDataFromCache(SESSION_INDEX);
        Assert.assertNull(sessionInfoData);
    }


    @Test
    public void testGetName() {

        SAMLLogoutHandler samlLogoutHandler = new SAMLLogoutHandler();
        Assert.assertEquals(samlLogoutHandler.getName(), "SAMLLogoutHandler");
    }

    private Event setupEvent(String eventName, String issuer) {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HashMap eventProperties = new HashMap();
        AuthenticationContext context = new AuthenticationContext();
        context.setRelyingParty(issuer);
        eventProperties.put(IdentityEventConstants.EventProperty.REQUEST, request);
        eventProperties.put(IdentityEventConstants.EventProperty.CONTEXT, context);
        Cookie[] cookies = new Cookie[1];
        Cookie cookie = new Cookie("samlssoTokenId", "samlssoTokenId");
        cookies[0] = cookie;
        when(request.getCookies()).thenReturn(cookies);
        Event event = new Event(eventName, eventProperties);
        return event;
    }

}
