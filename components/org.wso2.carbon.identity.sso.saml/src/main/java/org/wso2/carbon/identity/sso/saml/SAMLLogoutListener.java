package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.core.model.IdentityEventListenerConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;

import java.util.Map;

public class SAMLLogoutListener extends AbstractEventHandler {

    SAMLSSOService samlSsoService = new SAMLSSOService();

    private static Log log = LogFactory.getLog(org.wso2.carbon.identity.sso.saml.SAMLLogoutListener.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (event.getEventName().equals("SINGLE_LOGOUT")) {
            Map<String, Object> params = (Map<String, Object>) event.getEventProperties().get("params");
            String sessionTokenId = (String) params.get("samlssoTokenId");
            String serviceProvider = (String) params.get("serviceProvider");
            if (!sessionTokenId.isEmpty()) {
                try {
                    samlSsoService.doSingleLogout(sessionTokenId, serviceProvider);
                } catch (IdentityException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error in doing single logout in SAML.", e);
                    }
                }
            }

            if (log.isDebugEnabled()) {
                log.debug(event.getEventName() + " is handled by SamlLogoutListener");
            }
        }
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {
        IdentityEventListenerConfig identityEventListenerConfig = IdentityUtil.readEventListenerProperty
                (AbstractIdentityMessageHandler.class.getName(), this.getClass().getName());

        if (identityEventListenerConfig == null) {
            return true;
        }

        return Boolean.parseBoolean(identityEventListenerConfig.getEnable());
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        return true;
    }

    @Override
    public String getName() {
        return "SAML_LOGOUT_LISTENER";
    }
}
