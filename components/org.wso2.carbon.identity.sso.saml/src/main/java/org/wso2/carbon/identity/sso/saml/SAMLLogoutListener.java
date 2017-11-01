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

public class SAMLLogoutListener extends AbstractEventHandler {

    private static Log log = LogFactory.getLog(org.wso2.carbon.identity.sso.saml.SAMLLogoutListener.class);

    private SAMLSSOService samlSsoService = new SAMLSSOService();

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        String samlssoTokenId = null;
        if (StringUtils.equals(event.getEventName(), IdentityEventConstants.Event.SESSION_TERMINATE)) {
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
            String serviceProvider = context.getServiceProviderName();

            if (!samlssoTokenId.isEmpty() && !serviceProvider.isEmpty()) {
                try {
                    samlSsoService.doSingleLogout(samlssoTokenId, serviceProvider);
                } catch (IdentityException e) {
                    log.error("Error while doing single logout in SAML.", e);
                }
            }
        }
    }

    @Override
    public String getName() {
        return "SAML_LOGOUT_LISTENER";
    }

}
