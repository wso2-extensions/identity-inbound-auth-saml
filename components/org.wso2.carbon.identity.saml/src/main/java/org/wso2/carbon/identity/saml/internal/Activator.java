/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.wso2.carbon.identity.saml.internal;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.gateway.api.request.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.gateway.api.response.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.gateway.processor.handler.request.AbstractRequestHandler;
import org.wso2.carbon.identity.gateway.processor.handler.response.AbstractResponseHandler;
import org.wso2.carbon.identity.gateway.service.GatewayClaimResolverService;
import org.wso2.carbon.identity.saml.request.SAMLIdentityRequestFactory;
import org.wso2.carbon.identity.saml.response.HttpSAMLResponseFactory;
import org.wso2.carbon.identity.saml.response.SAMLIdpInitResponseHandler;
import org.wso2.carbon.identity.saml.response.SAMLSPInitResponseHandler;
import org.wso2.carbon.identity.saml.validator.IDPInitSAMLValidator;
import org.wso2.carbon.identity.saml.validator.SPInitSAMLValidator;

@Component(
        name = "org.wso2.carbon.identity.saml.component",
        immediate = true
)
public class Activator implements BundleActivator {

    private Logger log = LoggerFactory.getLogger(Activator.class);

    @Activate
    public void start(BundleContext bundleContext) throws Exception {
        try {
            bundleContext.registerService(HttpIdentityRequestFactory.class, new SAMLIdentityRequestFactory(), null);
            bundleContext.registerService(HttpIdentityResponseFactory.class, new HttpSAMLResponseFactory(), null);

            bundleContext.registerService(AbstractRequestHandler.class, new SPInitSAMLValidator(), null);
            bundleContext.registerService(AbstractRequestHandler.class, new IDPInitSAMLValidator(), null);

            bundleContext.registerService(AbstractResponseHandler.class, new SAMLSPInitResponseHandler(), null);
            bundleContext.registerService(AbstractResponseHandler.class, new SAMLIdpInitResponseHandler(), null);
        } catch (Throwable e) {
            System.out.println("Error while activating saml inbound component");
        }
    }

    /**
     * This is called when the bundle is stopped.
     *
     * @param bundleContext BundleContext of this bundle
     * @throws Exception Could be thrown while bundle stopping
     */
    public void stop(BundleContext bundleContext) throws Exception {
    }

    @Reference(
            name = "gateway.claim.resolver",
            service = GatewayClaimResolverService.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unSetGatewayClaimResolverService"
    )
    protected void addGatewayClaimResolverService(GatewayClaimResolverService gatewayClaimResolverService) {

        SAMLInboundServiceDataHolder.getInstance().setGatewayClaimResolverService(gatewayClaimResolverService);

        if (log.isDebugEnabled()) {
            log.debug("Binding GatewayClaimResolverService");
        }
    }

    protected void unSetGatewayClaimResolverService(GatewayClaimResolverService gatewayClaimResolverService) {

        SAMLInboundServiceDataHolder.getInstance().setGatewayClaimResolverService(null);

        if (log.isDebugEnabled()) {
            log.debug("Un-Binding GatewayClaimResolverService");
        }
    }
}
