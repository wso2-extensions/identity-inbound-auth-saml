package org.wso2.carbon.identity.saml.internal;

import org.wso2.carbon.identity.gateway.service.GatewayClaimResolverService;

public class SAMLInboundServiceDataHolder {

    private static SAMLInboundServiceDataHolder instance = new SAMLInboundServiceDataHolder();
    private GatewayClaimResolverService gatewayClaimResolverService = null;

    public GatewayClaimResolverService getGatewayClaimResolverService() {
        return gatewayClaimResolverService;
    }

    public void setGatewayClaimResolverService(GatewayClaimResolverService gatewayClaimResolverService) {
        this.gatewayClaimResolverService = gatewayClaimResolverService;
    }

    public static SAMLInboundServiceDataHolder getInstance() {
        return instance;
    }
}
