/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.listener.SessionContextMgtListener;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.SAML_SSO_TOKEN_ID_COOKIE;

/**
 * Session Context context listener implementation for the SAML.
 */
public class SAMLInboundSessionContextMgtListener implements SessionContextMgtListener {

    private static final Log log = LogFactory.getLog(SAMLInboundSessionContextMgtListener.class);
    private static final String INBOUND_TYPE = "samlsso";

    @Override
    public String getInboundType() {

        return INBOUND_TYPE;
    }

    @Override
    public Map<String, String> onPreCreateSession(String sessionId, HttpServletRequest httpServletRequest,
                                                  HttpServletResponse httpServletResponse,
                                                  AuthenticationContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Handling onPreCreateSession for samlsso.");
        }
        Cookie ssoTokenIdCookie = getTokenIdCookie(httpServletRequest);
        if (ssoTokenIdCookie != null) {
            sessionId = ssoTokenIdCookie.getValue();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("samlssoTokenId not present in the request. Hence creating new value.");
            }
            if (IdentityTenantUtil.isTenantedSessionsEnabled()) {
                // Add suffix to the session id for identify saml sso token id cookies which has a tenanted path.
                sessionId = UUIDGenerator.generateUUID() + SAMLSSOConstants.TENANT_QUALIFIED_TOKEN_ID_COOKIE_SUFFIX;
            } else {
                sessionId = UUIDGenerator.generateUUID();
            }
        }
        Map<String, String> map = new HashMap<>();
        map.put(SAML_SSO_TOKEN_ID_COOKIE, sessionId);
        return map;
    }

    @Override
    public Map<String, String> onPreUpdateSession(String sessionId, HttpServletRequest httpServletRequest,
                                               HttpServletResponse httpServletResponse,
                                               AuthenticationContext authenticationContext) {

        if (log.isDebugEnabled()) {
            log.debug("Handling onPreUpdateSession for samlsso.");
        }
        return this.onPreCreateSession(sessionId, httpServletRequest, httpServletResponse, authenticationContext);
    }

    private Cookie getTokenIdCookie(HttpServletRequest req) {

        Cookie[] cookies = req.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (StringUtils.equals(cookie.getName(), SAML_SSO_TOKEN_ID_COOKIE)) {
                    return cookie;
                }
            }
        }
        return null;
    }
}
