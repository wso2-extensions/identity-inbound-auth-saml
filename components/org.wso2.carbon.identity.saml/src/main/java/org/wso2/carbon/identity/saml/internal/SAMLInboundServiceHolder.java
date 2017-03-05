package org.wso2.carbon.identity.saml.internal;

import org.wso2.carbon.identity.gateway.service.GatewayClaimResolverService;

public class SAMLInboundServiceHolder {

    private static SAMLInboundServiceHolder instance = new SAMLInboundServiceHolder();
    private GatewayClaimResolverService gatewayClaimResolverService = null;

    public static SAMLInboundServiceHolder getInstance() {
        return instance;
    }

    public GatewayClaimResolverService getGatewayClaimResolverService() {
        return gatewayClaimResolverService;
    }

    public void setGatewayClaimResolverService(GatewayClaimResolverService gatewayClaimResolverService) {
        this.gatewayClaimResolverService = gatewayClaimResolverService;
    }
}
