/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.event.IdentityEventConstants.EventName;
import org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * SAML Logout Handler do Single Logout when session is terminated.
 */
public class SAMLLogoutHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(SAMLLogoutHandler.class);

    private SAMLSSOService samlSSOService = new SAMLSSOService();

    /**
     * Session termination event is handled to do single logout for SAML applications.
     *
     * @param event Session termination event
     * @throws IdentityEventException
     */
    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        String samlssoTokenId = null;
        String issuer = null;

        if (StringUtils.equals(event.getEventName(), EventName.SESSION_TERMINATE.name())) {
            samlssoTokenId = getSamlSSOTokenIdFromEvent(event);
            if (StringUtils.isNotBlank(samlssoTokenId)) {
                if (!isIDPInitiatedLogoutRequest(event)) {
                    issuer = this.getIssuerFromContext(event);
                }

                try {
                    samlSSOService.doSingleLogout(samlssoTokenId, issuer);
                } catch (IdentityException e) {
                    log.error("Error while SAML Logout Listener is doing single logout.", e);
                }
            } else {
                if (log.isDebugEnabled()) {
                    AuthenticationContext context = (AuthenticationContext) event.getEventProperties().
                            get(EventProperty.CONTEXT);
                    if (context != null) {
                        log.debug("There are no SAML participants in the session : " +
                                context.getSessionIdentifier());
                    } else {
                        log.debug("There are no SAML participants in the session.");
                    }
                }
            }
        }
    }

    @Override
    public String getName() {

        return "SAMLLogoutHandler";
    }

    /**
     * Method to retrieve samlssoTokenId from the event.
     *
     * @param event Session termination event.
     * @return samlssoTokenId.
     */
    protected String getSamlSSOTokenIdFromEvent(Event event) {

        String samlssoTokenId = null;
        if (event.getEventProperties().get(EventProperty.REQUEST) instanceof HttpServletRequest) {
            HttpServletRequest request = (HttpServletRequest) event.getEventProperties().get(EventProperty.REQUEST);
            if (request != null) {
                Cookie cookie = FrameworkUtils.getCookie(request, SAMLSSOConstants.SAML_SSO_TOKEN_ID_COOKIE);
                if (cookie != null) {
                    samlssoTokenId = cookie.getValue();
                }
            }
        }
        return samlssoTokenId;
    }

    /**
     * Method to check whether the logout request is initiated from IdP.
     *
     * @param event Session termination event.
     * @return Whether the logout request is initiated from IdP.
     */
    protected boolean isIDPInitiatedLogoutRequest(Event event) {

        boolean isIdpInitiated = true;
        HttpServletRequest request = (HttpServletRequest) event.getEventProperties().get(EventProperty.REQUEST);
        if (request != null) {
            String slo = request.getParameter(SAMLSSOConstants.QueryParameter.SLO.toString());
            AuthenticationContext context = (AuthenticationContext) event.getEventProperties()
                    .get(EventProperty.CONTEXT);

            if (context != null && slo == null) {
                isIdpInitiated = false;
            }
        }
        return isIdpInitiated;
    }

    /**
     * Method to retrieve the logout request issuer from the authentication context.
     *
     * @param event Session termination event.
     * @return Issuer.
     */
    protected String getIssuerFromContext(Event event) {

        AuthenticationContext context = (AuthenticationContext) event.getEventProperties().get(EventProperty.CONTEXT);
        return context.getRelyingParty();
    }

}
