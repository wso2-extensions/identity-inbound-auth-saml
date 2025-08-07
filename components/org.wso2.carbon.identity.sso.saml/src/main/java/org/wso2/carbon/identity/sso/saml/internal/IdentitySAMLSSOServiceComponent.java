/*
 * Copyright (c) 2005, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.sso.saml.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.equinox.http.helper.ContextPathServletAdaptor;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticationService;
import org.wso2.carbon.identity.application.authentication.framework.listener.SessionContextMgtListener;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.inbound.protocol.ApplicationInboundAuthConfigHandler;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.core.SAMLSSOServiceProviderManager;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.sso.saml.SAML2InboundAuthConfigHandler;
import org.wso2.carbon.identity.sso.saml.SAMLInboundSessionContextMgtListener;
import org.wso2.carbon.identity.sso.saml.SAMLLogoutHandler;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConfigServiceImpl;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.admin.FileBasedConfigManager;
import org.wso2.carbon.identity.sso.saml.extension.SAMLExtensionProcessor;
import org.wso2.carbon.identity.sso.saml.extension.eidas.EidasExtensionProcessor;
import org.wso2.carbon.identity.sso.saml.servlet.SAMLArtifactResolveServlet;
import org.wso2.carbon.identity.sso.saml.servlet.SAMLSSOProviderServlet;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.Servlet;

/**
 * Service component class for the SAML SSO service.
 */
@Component(
         name = "identity.sso.saml.component",
         immediate = true)
public class IdentitySAMLSSOServiceComponent {

    private static final Log log = LogFactory.getLog(IdentitySAMLSSOServiceComponent.class);
    private static int defaultSingleLogoutRetryCount = 5;

    private static ServerConfigurationService serverConfigurationService = null;
    private static long defaultSingleLogoutRetryInterval = 60000;

    private static String ssoRedirectPage = null;
    private static boolean useSamlSsoResponseJspPage = false;
    private static boolean useSamlSsoResponseHtmlPage = false;

    public static String getSsoRedirectHtml() {

        return ssoRedirectPage;
    }

    /**
     * @return if the saml sso response JSP page is available or not.
     */
    public static boolean isSAMLSSOResponseJspPageAvailable() {

        return useSamlSsoResponseJspPage;
    }

    /**
     * @return if the saml sso response HTML page is available or not.
     */
    public static boolean isSAMLSSOResponseHtmlPageAvailable() {

        return useSamlSsoResponseHtmlPage;
    }

    @Activate
    protected void activate(ComponentContext ctxt) {

        SAMLSSOUtil.setBundleContext(ctxt.getBundleContext());
        HttpService httpService = SAMLSSOUtil.getHttpService();
        // Register SAML SSO servlet
        Servlet samlSSOServlet = new ContextPathServletAdaptor(new SAMLSSOProviderServlet(),
                SAMLSSOConstants.SAMLSSO_URL);
        try {
            httpService.registerServlet(SAMLSSOConstants.SAMLSSO_URL, samlSSOServlet, null, null);
        } catch (Exception e) {
            String errMsg = "Error when registering SAML SSO Servlet via the HttpService.";
            log.error(errMsg, e);
            throw new RuntimeException(errMsg, e);
        }
        // Register SAML artifact resolve servlet
        Servlet samlArtifactResolveServlet = new ContextPathServletAdaptor(new SAMLArtifactResolveServlet(),
                SAMLSSOConstants.SAML_ARTIFACT_RESOLVE_URL);
        try {
            httpService.registerServlet(SAMLSSOConstants.SAML_ARTIFACT_RESOLVE_URL, samlArtifactResolveServlet,
                    null, null);
        } catch (Exception e) {
            throw new RuntimeException("Error when registering SAML Artifact Resolve Servlet via the HttpService.", e);
        }

        // Register a SSOServiceProviderConfigManager object as an OSGi Service
        ctxt.getBundleContext().registerService(SSOServiceProviderConfigManager.class.getName(),
                SSOServiceProviderConfigManager.getInstance(), null);

        SAMLSSOConfigServiceImpl samlSSOConfigService = new SAMLSSOConfigServiceImpl();
        IdentitySAMLSSOServiceComponentHolder.getInstance().setSamlSSOConfigService(samlSSOConfigService);
        ServiceRegistration samlSsoConfigServiceRegistration =
                ctxt.getBundleContext().registerService(SAMLSSOConfigServiceImpl.class, samlSSOConfigService, null);
        SAML2InboundAuthConfigHandler saml2InboundAuthConfigHandler = new SAML2InboundAuthConfigHandler();
        IdentitySAMLSSOServiceComponentHolder.getInstance().setSaml2InboundAuthConfigHandler(
                saml2InboundAuthConfigHandler);
        ctxt.getBundleContext().registerService(ApplicationInboundAuthConfigHandler.class,
                saml2InboundAuthConfigHandler, null);
        SAMLSSOUtil.setSamlssoConfigService(samlSSOConfigService);

        if (samlSsoConfigServiceRegistration != null) {
            if (log.isDebugEnabled()) {
                log.debug("SAMLSSOConfigService registered.");
            }
        } else {
            log.error("SAMLSSOConfigService could not be registered.");
        }

        Path redirectHtmlPath = null;
        try {
            IdentityUtil.populateProperties();
            SAMLSSOUtil.setSingleLogoutRetryCount(Integer.parseInt(
                    IdentityUtil.getProperty(IdentityConstants.ServerConfig.SINGLE_LOGOUT_RETRY_COUNT)));
            SAMLSSOUtil.setSingleLogoutRetryInterval(Long.parseLong(IdentityUtil.getProperty(
                    IdentityConstants.ServerConfig.SINGLE_LOGOUT_RETRY_INTERVAL)));

            SAMLSSOUtil.setResponseBuilder(IdentityUtil.getProperty("SSOService.SAMLSSOResponseBuilder"));
            SAMLSSOUtil.setIdPInitSSOAuthnRequestValidator(IdentityUtil.getProperty("SSOService.IdPInitSSOAuthnRequestValidator"));
            SAMLSSOUtil.setSPInitSSOAuthnRequestProcessor(IdentityUtil.getProperty("SSOService.SPInitSSOAuthnRequestProcessor"));
            SAMLSSOUtil.setSPInitLogoutRequestProcessor(IdentityUtil.getProperty("SSOService.SPInitLogoutRequestProcessor"));
            SAMLSSOUtil.setIdPInitLogoutRequestProcessor(IdentityUtil.getProperty("SSOService.IdPInitLogoutRequestProcessor"));
            SAMLSSOUtil.setIdPInitSSOAuthnRequestProcessor(IdentityUtil.getProperty("SSOService.IdPInitSSOAuthnRequestProcessor"));

            if (log.isDebugEnabled()) {
                log.debug("IdPInitSSOAuthnRequestValidator is set to " +
                        IdentityUtil.getProperty("SSOService.IdPInitSSOAuthnRequestValidator"));
                log.debug("SPInitSSOAuthnRequestValidator is set to " +
                        IdentityUtil.getProperty("SSOService.SPInitSSOAuthnRequestValidator"));
                log.debug("SPInitSSOAuthnRequestProcessor is set to " +
                        IdentityUtil.getProperty("SSOService.SPInitSSOAuthnRequestProcessor"));
                log.debug("SPInitLogoutRequestProcessor is set to " +
                        IdentityUtil.getProperty("SSOService.SPInitLogoutRequestProcessor"));
                log.debug("IdPInitLogoutRequestProcessor is set to " +
                        IdentityUtil.getProperty("SSOService.IdPInitLogoutRequestProcessor"));
                log.debug("IdPInitSSOAuthnRequestProcessor is set to " +
                        IdentityUtil.getProperty("SSOService.IdPInitSSOAuthnRequestProcessor"));
                log.debug("Single logout retry count is set to " + SAMLSSOUtil.getSingleLogoutRetryCount());
                log.debug("Single logout retry interval is set to " +
                        SAMLSSOUtil.getSingleLogoutRetryInterval() + " in seconds.");
            }

            Path redirectJspFilePath = Paths.get(CarbonUtils.getCarbonHome(), "repository", "deployment",
                    "server", "webapps", "authenticationendpoint", "samlsso_response.jsp");
            if (Files.exists(redirectJspFilePath)) {
                useSamlSsoResponseJspPage = true;
                if (log.isDebugEnabled()) {
                    log.debug(" SAML SSO response JSP page is found at : " + redirectJspFilePath);
                }
            } else {
                redirectHtmlPath = Paths.get(CarbonUtils.getCarbonHome(), "repository", "resources",
                        "identity", "pages", "samlsso_response.html");
                if (Files.exists(redirectHtmlPath)) {
                    useSamlSsoResponseHtmlPage = true;
                    ssoRedirectPage = new String(Files.readAllBytes(redirectHtmlPath), StandardCharsets.UTF_8);
                    if (log.isDebugEnabled()) {
                        log.debug(" SAML SSO response HTML page is found at : " + redirectHtmlPath);
                    }
                }
            }

            FileBasedConfigManager.getInstance().addServiceProviders();

            // Register EidasExtensionProcessor as an OSGi Service
            ctxt.getBundleContext().registerService(SAMLExtensionProcessor.class.getName(),
                    new EidasExtensionProcessor(), null);

            ServiceRegistration oauthApplicationMgtListener = ctxt.getBundleContext()
                    .registerService(ApplicationMgtListener.class.getName(), new SAMLApplicationMgtListener(), null);
            if (oauthApplicationMgtListener != null) {
                if (log.isDebugEnabled()) {
                    log.debug("SAML - ApplicationMgtListener registered.");
                }
            } else {
                log.error("SAML - ApplicationMgtListener could not be registered.");
            }

            ctxt.getBundleContext().registerService(AbstractEventHandler.class.getName(),
                    new SAMLLogoutHandler(), null);
            ctxt.getBundleContext().registerService(SessionContextMgtListener.class.getName(),
                    new SAMLInboundSessionContextMgtListener(), null);

            if (log.isDebugEnabled()) {
                log.debug("Identity SAML SSO bundle is activated");
            }
        } catch (NoSuchFileException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to find SAML SSO response page in : " + redirectHtmlPath);
            }
        } catch (Throwable e) {
            SAMLSSOUtil.setSingleLogoutRetryCount(defaultSingleLogoutRetryCount);
            SAMLSSOUtil.setSingleLogoutRetryInterval(defaultSingleLogoutRetryInterval);
            if (log.isDebugEnabled()) {
                log.debug("Failed to load the single logout retry count and interval values." +
                        " Default values for retry count: " + defaultSingleLogoutRetryCount +
                        " and interval: " + defaultSingleLogoutRetryInterval + " will be used.", e);
            }
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        SAMLSSOUtil.setBundleContext(null);
        if (log.isDebugEnabled()) {
            log.info("Identity SAML SSO bundle is deactivated");
        }
    }

    /**
     * Set Application management service implementation
     *
     * @param applicationMgtService Application management service
     */
    @Reference(
            name = "application.mgt.service",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationMgtService"
    )
    protected void setApplicationMgtService(ApplicationManagementService applicationMgtService) {
        if (log.isDebugEnabled()) {
            log.debug("ApplicationManagementService set in SAML SSO bundle");
        }
        SAMLSSOUtil.setApplicationMgtService(applicationMgtService);
    }

    /**
     * Unset Application management service implementation
     *
     * @param applicationMgtService Application management service
     */
    protected void unsetApplicationMgtService(ApplicationManagementService applicationMgtService) {
        if (log.isDebugEnabled()) {
            log.debug("ApplicationManagementService unset in SAML SSO bundle");
        }
        SAMLSSOUtil.setApplicationMgtService(null);
    }

    @Reference(
            name = "registry.service",
            service = org.wso2.carbon.registry.core.service.RegistryService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRegistryService")
    protected void setRegistryService(RegistryService registryService) {

        if (log.isDebugEnabled()) {
            log.debug("RegistryService set in Identity SAML SSO bundle");
        }
        try {
            SAMLSSOUtil.setRegistryService(registryService);
        } catch (Throwable e) {
            log.error("Failed to get a reference to the Registry in SAML SSO bundle", e);
        }
    }

    protected void unsetRegistryService(RegistryService registryService) {

        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in SAML SSO bundle");
        }
        SAMLSSOUtil.setRegistryService(null);
    }

    @Reference(
            name = "user.realmservice.default",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the SAML SSO bundle");
        }
        SAMLSSOUtil.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the SAML SSO bundle");
        }
        SAMLSSOUtil.setRegistryService(null);
    }

    @Reference(
            name = "config.context.service",
            service = org.wso2.carbon.utils.ConfigurationContextService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetConfigurationContextService")
    protected void setConfigurationContextService(ConfigurationContextService configCtxService) {

        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is set in the SAML SSO bundle");
        }
        SAMLSSOUtil.setConfigCtxService(configCtxService);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService configCtxService) {

        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is unset in the SAML SSO bundle");
        }
        SAMLSSOUtil.setConfigCtxService(null);
    }

    @Reference(
            name = "osgi.httpservice",
            service = org.osgi.service.http.HttpService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetHttpService")
    protected void setHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in the SAML SSO bundle");
        }
        SAMLSSOUtil.setHttpService(httpService);
    }

    protected void unsetHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the SAML SSO bundle");
        }
        SAMLSSOUtil.setHttpService(null);
    }

    public static ServerConfigurationService getServerConfigurationService() {

        return IdentitySAMLSSOServiceComponent.serverConfigurationService;
    }

    protected void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        if (log.isDebugEnabled()) {
            log.debug("Set the ServerConfiguration Service");
        }
        IdentitySAMLSSOServiceComponent.serverConfigurationService = serverConfigurationService;
    }

    protected void unsetServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        if (log.isDebugEnabled()) {
            log.debug("Unset the ServerConfiguration Service");
        }
        IdentitySAMLSSOServiceComponent.serverConfigurationService = null;
    }

    @Reference(
            name = "identityCoreInitializedEventService",
            service = org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService"
    )
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    /**
     * Set SAML Extension Processors
     *
     * @param extensionProcessor Extension Processor
     */
    @Reference(
            name = "saml.extension.processor",
            service = SAMLExtensionProcessor.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetExtensionProcessor"
    )
    protected void setExtensionProcessor(SAMLExtensionProcessor extensionProcessor) {

        if (log.isDebugEnabled()) {
            log.debug("Extension Processor: " + extensionProcessor.getClass() + " set in SAML SSO bundle");
        }
        SAMLSSOUtil.addExtensionProcessors(extensionProcessor);
    }

    /**
     * Unset SAML Extension Processors
     *
     * @param extensionProcessor Extension Processor
     */
    protected void unsetExtensionProcessor(SAMLExtensionProcessor extensionProcessor) {

        if (log.isDebugEnabled()) {
            log.debug("Extension Processor: " + extensionProcessor.getClass() + " unset in SAML SSO bundle");
        }
        SAMLSSOUtil.removeExtensionProcessors(extensionProcessor);
    }

    @Reference(
            name = "saml.sso.service.provider.manager",
            service = org.wso2.carbon.identity.core.SAMLSSOServiceProviderManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetSAMLSSOServiceProviderManager")
    protected void setSAMLSSOServiceProviderManager(SAMLSSOServiceProviderManager samlSSOServiceProviderManager) {

        IdentitySAMLSSOServiceComponentHolder.getInstance().setSAMLSSOServiceProviderManager(samlSSOServiceProviderManager);
        if (log.isDebugEnabled()) {
            log.debug("SAMLSSOServiceProviderManager set in to bundle");
        }
    }

    protected void unsetSAMLSSOServiceProviderManager(SAMLSSOServiceProviderManager samlSSOServiceProviderManager) {

        IdentitySAMLSSOServiceComponentHolder.getInstance().setSAMLSSOServiceProviderManager(null);
        if (log.isDebugEnabled()) {
            log.debug("SAMLSSOServiceProviderManager unset in to bundle");
        }
    }

    @Reference(
            name = "identity.application.authentication.framework",
            service = ApplicationAuthenticationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationAuthenticationService"
    )
    protected void setApplicationAuthenticationService(
            ApplicationAuthenticationService applicationAuthenticationService) {
        /* Reference ApplicationAuthenticationService service to guarantee that this component will wait until
        authentication framework is started. */
    }

    protected void unsetApplicationAuthenticationService(
            ApplicationAuthenticationService applicationAuthenticationService) {
        /* Reference ApplicationAuthenticationService service to guarantee that this component will wait until
        authentication framework is started. */
    }
}
