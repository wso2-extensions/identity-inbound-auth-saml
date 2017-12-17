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

import org.opensaml.DefaultBootstrap;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.session.SessionInfoData;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * Unit Tests for SAMLLogoutListener.
 */
@PrepareForTest({HttpServletRequest.class, IdentityProviderManager.class, DefaultBootstrap.class, SAMLSSOUtil.class})
public class SAMLLogoutListenerTest extends PowerMockTestCase {

    @Test
    public void testHandleEvent() throws Exception {

        Event event = setupEvent(IdentityEventConstants.EventName.SESSION_TERMINATE.name());
        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

        Map<String, SAMLSSOServiceProviderDO> serviceProviderList = new ConcurrentHashMap<>();
        SAMLSSOServiceProviderDO serviceProviderDO = new SAMLSSOServiceProviderDO();
        serviceProviderDO.setIssuer("relyingParty");
        serviceProviderList.put("key", serviceProviderDO);
        SessionInfoData sessionInfoData = new SessionInfoData();
        sessionInfoData.addServiceProvider("relyingParty", serviceProviderDO, null);

        SSOSessionPersistenceManager.addSessionIndexToCache("samlssoTokenId", "theSessionIndex");
        SSOSessionPersistenceManager.addSessionInfoDataToCache("theSessionIndex", sessionInfoData);
        SAMLLogoutListener samlLogoutListener = new SAMLLogoutListener();
        samlLogoutListener.handleEvent(event);
    }

    @Test
    public void testGetName() {
        SAMLLogoutListener samlLogoutListener = new SAMLLogoutListener();
        Assert.assertEquals(samlLogoutListener.getName(), "SAML_LOGOUT_LISTENER");
    }

    private Event setupEvent(String eventName) {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HashMap eventProperties = new HashMap();
        AuthenticationContext context = new AuthenticationContext();
        context.setRelyingParty("relyingParty");
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
