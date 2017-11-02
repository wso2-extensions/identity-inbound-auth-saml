/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * SAML Logout Handler do Single Logout when session is terminated.
 */

public class SAMLLogoutListener extends AbstractEventHandler {

    private static Log log = LogFactory.getLog(org.wso2.carbon.identity.sso.saml.SAMLLogoutListener.class);

    private SAMLSSOService samlSsoService = new SAMLSSOService();

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        String samlssoTokenId = null;
        if (StringUtils.equals(event.getEventName(), IdentityEventConstants.EventName.SESSION_TERMINATE.toString())) {
            HttpServletRequest request = (HttpServletRequest) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.REQUEST);
            AuthenticationContext context = (AuthenticationContext) event.getEventProperties()
                    .get(IdentityEventConstants.EventProperty.CONTEXT);
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (StringUtils.equals(cookie.getName(), "samlssoTokenId")) {
                        samlssoTokenId = cookie.getValue();
                    }
                }
            }
            String issuer = context.getServiceProviderName();

            if (!samlssoTokenId.isEmpty() && !issuer.isEmpty()) {
                try {
                    samlSsoService.doSingleLogout(samlssoTokenId, issuer);
                } catch (IdentityException e) {
                    log.error("Error while doing single logout for " + issuer + ".", e);
                }
            }
        }
    }

    @Override
    public String getName() {
        return "SAML_LOGOUT_LISTENER";
    }

}
