/*
 * Copyright (c) 2010-2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
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

package org.wso2.carbon.identity.sso.saml.util;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpService;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.SAML2SSOFederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.IdentityRegistryResources;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConfigServiceImpl;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.builders.DefaultResponseBuilder;
import org.wso2.carbon.identity.sso.saml.builders.ErrorResponseBuilder;
import org.wso2.carbon.identity.sso.saml.builders.ResponseBuilder;
import org.wso2.carbon.identity.sso.saml.builders.SingleLogoutMessageBuilder;
import org.wso2.carbon.identity.sso.saml.builders.X509CredentialImpl;
import org.wso2.carbon.identity.sso.saml.builders.assertion.SAMLAssertionBuilder;
import org.wso2.carbon.identity.sso.saml.builders.encryption.SSOEncrypter;
import org.wso2.carbon.identity.sso.saml.builders.signature.DefaultSSOSigner;
import org.wso2.carbon.identity.sso.saml.builders.signature.SSOSigner;
import org.wso2.carbon.identity.sso.saml.dto.QueryParamDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SingleLogoutRequestDTO;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ClientException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.extension.SAMLExtensionProcessor;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponentHolder;
import org.wso2.carbon.identity.sso.saml.processors.IdPInitLogoutRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.IdPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.SPInitLogoutRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.SPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.session.SessionInfoData;
import org.wso2.carbon.identity.sso.saml.validators.IdPInitSSOAuthnRequestValidator;
import org.wso2.carbon.identity.sso.saml.validators.SAML2HTTPRedirectSignatureValidator;
import org.wso2.carbon.identity.sso.saml.validators.SPInitSSOAuthnRequestValidator;
import org.wso2.carbon.identity.sso.saml.validators.SSOAuthnRequestValidator;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.service.TenantRegistryLoader;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.security.KeystoreUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.NameFormat;
import static org.wso2.carbon.identity.sso.saml.SAMLSSOConstants.SAML_REQUEST;

public class SAMLSSOUtil {

    private static final Log log = LogFactory.getLog(SAMLSSOUtil.class);
    private static final Set<Character> UNRESERVED_CHARACTERS = new HashSet<>();
    private static final ThreadLocal<Boolean> isSaaSApplication = new ThreadLocal<>();
    private static final ThreadLocal<String> userTenantDomainThreadLocal = new ThreadLocal<>();
    private static final String DefaultAssertionBuilder = "org.wso2.carbon.identity.sso.saml.builders.assertion.DefaultSAMLAssertionBuilder";

    static {
        for (char c = 'a'; c <= 'z'; c++)
            UNRESERVED_CHARACTERS.add(Character.valueOf(c));

        for (char c = 'A'; c <= 'Z'; c++)
            UNRESERVED_CHARACTERS.add(Character.valueOf(c));

        for (char c = '0'; c <= '9'; c++)
            UNRESERVED_CHARACTERS.add(Character.valueOf(c));

        UNRESERVED_CHARACTERS.add(Character.valueOf('-'));
        UNRESERVED_CHARACTERS.add(Character.valueOf('.'));
        UNRESERVED_CHARACTERS.add(Character.valueOf('_'));
        UNRESERVED_CHARACTERS.add(Character.valueOf('~'));
    }

    private static RegistryService registryService;
    private static TenantRegistryLoader tenantRegistryLoader;
    private static BundleContext bundleContext;
    private static RealmService realmService;
    private static ConfigurationContextService configCtxService;
    private static HttpService httpService;
    private static boolean isBootStrapped = false;
    private static int singleLogoutRetryCount = 5;
    private static long singleLogoutRetryInterval = 60000;
    private static String responseBuilderClassName = null;
    private static SAMLAssertionBuilder samlAssertionBuilder = null;
    private static SSOEncrypter ssoEncrypter = null;
    private static SSOSigner ssoSigner = null;
    private static SAML2HTTPRedirectSignatureValidator samlHTTPRedirectSignatureValidator = null;
    private static String sPInitSSOAuthnRequestValidatorClassName = null;
    private static String iDPInitSSOAuthnRequestValidatorClassName = null;
    private static ThreadLocal tenantDomainInThreadLocal = new ThreadLocal();
    private static ThreadLocal issuerWithQualifierInThreadLocal = new ThreadLocal();
    private static String issuerQualifier = null;
    private static String idPInitLogoutRequestProcessorClassName = null;
    private static String sPInitSSOAuthnRequestProcessorClassName = null;
    private static String sPInitLogoutRequestProcessorClassName = null;
    private static Boolean spCertificateExpiryValidationEnabled;
    private static int samlAuthenticationRequestValidityPeriod = 5*60;
    private static ApplicationManagementService applicationMgtService;
    private static SAMLSSOConfigServiceImpl samlssoConfigService;
    private static volatile List<SAMLExtensionProcessor> extensionProcessors;

    private SAMLSSOUtil() {
    }

    public static boolean isSaaSApplication() {

        Boolean value = isSaaSApplication.get();

        if (value != null) {
            return value;
        }

        return false;
    }

    /**
     * Check whether certificate expiration enabled
     * @return
     */
    public static boolean isSpCertificateExpiryValidationEnabled() {

        spCertificateExpiryValidationEnabled = Boolean.parseBoolean(IdentityUtil.getProperty(
                SAMLSSOConstants.SAML_SP_CERTIFICATE_EXPIRY_VALIDATION_ENABLED));
        return spCertificateExpiryValidationEnabled;
    }

    /**
     * Check whether use the application certificate to encrypt the SAML assertion.
     * @return true if use the app certificate.
     */
    public static boolean isSAMLAssertionEncryptWithAppCert() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(
                SAMLSSOConstants.SAML_ASSERTION_ENCRYPT_WITH_APP_CERT));
    }

    /**
     * Check whether SAML Authentication request validity period enabled
     * @return
     */
    public static boolean isSAMLAuthenticationRequestValidityPeriodEnabled() {
        return Boolean.parseBoolean(IdentityUtil.getProperty(SAMLSSOConstants
                .SAML2_AUTHENTICATION_REQUEST_VALIDITY_PERIOD_ENABLED));
    }

    /**
     * Get the configured SAML request validity period
     * @return
     */
    public static int getSAMLAuthenticationRequestValidityPeriod() {

        if (IdentityUtil.getProperty(SAMLSSOConstants.SAML2_AUTHENTICATION_REQUEST_VALIDITY_PERIOD) != null) {
            samlAuthenticationRequestValidityPeriod = Integer.parseInt(IdentityUtil.getProperty(
                    SAMLSSOConstants.SAML2_AUTHENTICATION_REQUEST_VALIDITY_PERIOD));
        }
        return samlAuthenticationRequestValidityPeriod;
    }

    public static void setIsSaaSApplication(boolean isSaaSApp) {
        isSaaSApplication.set(isSaaSApp);
    }

    public static void removeSaaSApplicationThreaLocal() {
        isSaaSApplication.remove();
    }

    public static String getUserTenantDomain() {

        return userTenantDomainThreadLocal.get();
    }

    public static void setUserTenantDomain(String tenantDomain) throws UserStoreException, IdentityException {

        tenantDomain = validateTenantDomain(tenantDomain);
        if (tenantDomain != null) {
            userTenantDomainThreadLocal.set(tenantDomain);
        }
    }

    public static void removeUserTenantDomainThreaLocal() {
        userTenantDomainThreadLocal.remove();
    }

    public static BundleContext getBundleContext() {
        return SAMLSSOUtil.bundleContext;
    }

    public static void setBundleContext(BundleContext bundleContext) {
        SAMLSSOUtil.bundleContext = bundleContext;
    }

    public static RegistryService getRegistryService() {
        return registryService;
    }

    public static void setRegistryService(RegistryService registryService) {
        SAMLSSOUtil.registryService = registryService;
    }

    public static void setApplicationMgtService(ApplicationManagementService applicationMgtService) {

        SAMLSSOUtil.applicationMgtService = applicationMgtService;
    }

    public static ApplicationManagementService getApplicationMgtService() {

        return applicationMgtService;
    }

    public static SAMLSSOConfigServiceImpl getSAMLSSOConfigService() {

        return samlssoConfigService;
    }

    public static void setSamlssoConfigService(SAMLSSOConfigServiceImpl samlssoConfigService) {

        SAMLSSOUtil.samlssoConfigService = samlssoConfigService;
    }

    public static TenantRegistryLoader getTenantRegistryLoader() {
        return tenantRegistryLoader;
    }

    public static void setTenantRegistryLoader(TenantRegistryLoader tenantRegistryLoader) {
        SAMLSSOUtil.tenantRegistryLoader = tenantRegistryLoader;
    }

    public static RealmService getRealmService() {
        return realmService;
    }

    public static void setRealmService(RealmService realmService) {
        SAMLSSOUtil.realmService = realmService;
    }

    public static ConfigurationContextService getConfigCtxService() {
        return configCtxService;
    }

    public static void setConfigCtxService(ConfigurationContextService configCtxService) {
        SAMLSSOUtil.configCtxService = configCtxService;
    }

    public static HttpService getHttpService() {
        return httpService;
    }

    public static void setHttpService(HttpService httpService) {
        SAMLSSOUtil.httpService = httpService;
    }

    /**
     * Get extension processors.
     *
     * @return list of extension processors
     */
    public static List<SAMLExtensionProcessor> getExtensionProcessors() {
        return extensionProcessors;
    }

    /**
     * Add extension processors.
     *
     * @param extensionProcessor Extension processor
     */
    public static void addExtensionProcessors(SAMLExtensionProcessor extensionProcessor) {
        if (SAMLSSOUtil.extensionProcessors == null) {
            SAMLSSOUtil.extensionProcessors = new ArrayList<>();
            SAMLSSOUtil.extensionProcessors.add(extensionProcessor);
        } else {
            SAMLSSOUtil.extensionProcessors.add(extensionProcessor);
        }
    }

    /**
     * Remove extension processor.
     *
     * @param extensionProcessor Extension processor
     */
    public static void removeExtensionProcessors(SAMLExtensionProcessor extensionProcessor) {

        if (SAMLSSOUtil.extensionProcessors != null) {
            Iterator<SAMLExtensionProcessor> iterator = extensionProcessors.iterator();
            while (iterator.hasNext()) {
                if (iterator.next().getClass().equals(extensionProcessor.getClass())) {
                    iterator.remove();
                }
            }
        }
    }

    /**
     * Constructing the AuthnRequest Object from a String
     *
     * @param authReqStr Decoded AuthReq String
     * @return AuthnRequest Object
     * @throws org.wso2.carbon.identity.base.IdentityException
     */
    public static XMLObject unmarshall(String authReqStr) throws IdentityException {
        InputStream inputStream = null;
        try {
            doBootstrap();
            inputStream = new ByteArrayInputStream(authReqStr.trim().getBytes(StandardCharsets.UTF_8));
            return XMLObjectSupport.unmarshallFromInputStream(
                    XMLObjectProviderRegistrySupport.getParserPool(), inputStream);
        } catch (XMLParserException e) {
            throw new IdentitySAML2ClientException("Error in constructing AuthRequest from the encoded String ", e);
        } catch (Exception e) {
            log.error("Error in constructing AuthRequest from the encoded String", e);
            throw IdentityException.error(
                    "Error in constructing AuthRequest from the encoded String ",
                    e);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    log.error("Error while closing the stream", e);
                }
            }
        }
    }

    /**
     * Serialize the Auth. Request
     *
     * @param xmlObject
     * @return serialized auth. req
     */
    public static String marshall(XMLObject xmlObject) throws IdentityException {

        ByteArrayOutputStream byteArrayOutputStrm = null;
        try {
            doBootstrap();
            System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                    "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");

            MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);

            byteArrayOutputStrm = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(byteArrayOutputStrm);
            writer.write(element, output);
            return byteArrayOutputStrm.toString("UTF-8");
        } catch (Exception e) {
            log.error("Error Serializing the SAML Response");
            throw IdentityException.error("Error Serializing the SAML Response", e);
        } finally {
            if (byteArrayOutputStrm != null) {
                try {
                    byteArrayOutputStrm.close();
                } catch (IOException e) {
                    log.error("Error while closing the stream", e);
                }
            }
        }
    }

    /**
     * Encoding the response
     *
     * @param xmlString String to be encoded
     * @return encoded String
     */
    public static String encode(String xmlString) {
        // Encoding the message
        String encodedRequestMessage =
                Base64Support.encode(xmlString.getBytes(StandardCharsets.UTF_8),
                        Base64Support.UNCHUNKED);
        return encodedRequestMessage.trim();
    }

    /**
     * Decoding and deflating the encoded AuthReq
     *
     * @param encodedStr encoded AuthReq
     * @return decoded AuthReq
     */
    public static String decode(String encodedStr) throws IdentityException {
        try {
            org.apache.commons.codec.binary.Base64 base64Decoder =
                    new org.apache.commons.codec.binary.Base64();
            byte[] xmlBytes = encodedStr.getBytes("UTF-8");
            byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

            try {
                Inflater inflater = new Inflater(true);
                inflater.setInput(base64DecodedByteArray);
                byte[] xmlMessageBytes = new byte[5000];
                int resultLength = inflater.inflate(xmlMessageBytes);

                if (!inflater.finished()) {
                    throw new IdentitySAML2ClientException("End of the compressed data stream has NOT been reached.");
                }

                inflater.end();
                String decodedString = new String(xmlMessageBytes, 0, resultLength, "UTF-8");
                if (log.isDebugEnabled()) {
                    log.debug("Request message " + decodedString);
                }
                return decodedString;

            } catch (DataFormatException e) {
                ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(base64DecodedByteArray);
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                InflaterInputStream iis = new InflaterInputStream(byteArrayInputStream);
                byte[] buf = new byte[1024];
                int count = iis.read(buf);
                while (count != -1) {
                    byteArrayOutputStream.write(buf, 0, count);
                    count = iis.read(buf);
                }
                iis.close();
                String decodedStr = new String(byteArrayOutputStream.toByteArray(), StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("Request message " + decodedStr, e);
                }
                return decodedStr;
            }
        } catch (IllegalArgumentException e) {
            throw new IdentitySAML2ClientException("Error when decoding the SAML Request. " +
                    "Invalid arguments provided.", e);
        } catch (IOException e) {
            throw new IdentitySAML2ClientException("Error when decoding the SAML Request.", e);
        }

    }

    public static String decodeForPost(String encodedStr)
            throws IdentityException {
        try {
            org.apache.commons.codec.binary.Base64 base64Decoder = new org.apache.commons.codec.binary.Base64();
            byte[] xmlBytes = encodedStr.getBytes("UTF-8");
            byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

            String decodedString = new String(base64DecodedByteArray, "UTF-8");
            if (log.isDebugEnabled()) {
                log.debug("Request message " + decodedString);
            }
            return decodedString;

        } catch (IOException e) {
            throw IdentityException.error(
                    "Error when decoding the SAML Request.", e);
        }

    }

    /**
     * Get the Issuer
     *
     * @return Issuer
     */
    public static Issuer getIssuer() throws IdentityException {

        return getIssuerFromTenantDomain(getTenantDomainFromThreadLocal());
    }

    public static Issuer getIssuerFromTenantDomain(String tenantDomain) throws IdentityException {

        // If an Entity ID Alias is provided, that is returned as the issuer.
        Issuer entityIDAliasFromSP = getEntityIDAliasFromSP(tenantDomain);
        if (entityIDAliasFromSP != null) {
            return entityIDAliasFromSP;
        }

        Issuer issuer = new IssuerBuilder().buildObject();
        String idPEntityId = null;
        IdentityProvider identityProvider;
        int tenantId;

        if (StringUtils.isEmpty(tenantDomain) || "null".equals(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            tenantId = MultitenantConstants.SUPER_TENANT_ID;
        } else {
            try {
                tenantId = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
            } catch (UserStoreException e) {
                throw IdentityException.error("Error occurred while retrieving tenant id from tenant domain", e);
            }

            if(MultitenantConstants.INVALID_TENANT_ID == tenantId) {
                throw IdentityException.error("Invalid tenant domain - '" + tenantDomain + "'" );
            }
        }

        IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);

        try {
            identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw IdentityException.error(
                    "Error occurred while retrieving Resident Identity Provider information for tenant " +
                            tenantDomain, e);
        }
        FederatedAuthenticatorConfig[] authnConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        for (FederatedAuthenticatorConfig config : authnConfigs) {
            if (IdentityApplicationConstants.Authenticator.SAML2SSO.NAME.equals(config.getName())) {
                SAML2SSOFederatedAuthenticatorConfig samlFedAuthnConfig = new SAML2SSOFederatedAuthenticatorConfig(config);
                idPEntityId = samlFedAuthnConfig.getIdpEntityId();
            }
        }
        if (idPEntityId == null) {
            idPEntityId = IdentityUtil.getProperty(IdentityConstants.ServerConfig.ENTITY_ID);
        }
        issuer.setValue(idPEntityId);
        issuer.setFormat(SAMLSSOConstants.NAME_ID_POLICY_ENTITY);
        return issuer;
    }

    /**
     * Override Issuer value with IdPEntityIDAlias
     *
     * @param tenantDomain
     * @return issuer with its value set to IdP Entity ID Alias
     * @throws IdentityException
     */
    private static Issuer getEntityIDAliasFromSP(String tenantDomain) throws IdentityException {

        String currentSP = getIssuerWithQualifierInThreadLocal();
        if (StringUtils.isEmpty(currentSP)) {
            return null;
        }
        SAMLSSOServiceProviderDO sp = getSPConfig(tenantDomain, currentSP);
        if (sp != null && StringUtils.isNotBlank(sp.getIdpEntityIDAlias())) {
            Issuer issuer = new IssuerBuilder().buildObject();
            issuer.setValue(sp.getIdpEntityIDAlias());
            issuer.setFormat(SAMLSSOConstants.NAME_ID_POLICY_ENTITY);
            return issuer;
        }
        return null;
    }

    /**
     *
     * @param tenantDomain
     * @return set of destination urls of resident identity provider
     * @throws IdentityException
     */

    public static List<String> getDestinationFromTenantDomain(String tenantDomain) throws IdentityException {

        List<String> destinationURLs = new ArrayList<String>();
        IdentityProvider identityProvider;

        try {
            identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            throw IdentityException.error(
                    "Error occurred while retrieving Resident Identity Provider information for tenant " +
                            tenantDomain, e);
        }
        FederatedAuthenticatorConfig[] authnConfigs = identityProvider.getFederatedAuthenticatorConfigs();
        destinationURLs.addAll(IdentityApplicationManagementUtil.getPropertyValuesForNameStartsWith(authnConfigs,
                IdentityApplicationConstants.Authenticator.SAML2SSO.NAME, IdentityApplicationConstants.Authenticator
                        .SAML2SSO.DESTINATION_URL_PREFIX));
        if (destinationURLs.size() == 0) {

            String destinationURL = resolveUrl(SAMLSSOConstants.SAMLSSO_URL, IdentityUtil.getProperty
                    (IdentityConstants.ServerConfig.SSO_IDP_URL));
            destinationURLs.add(destinationURL);

            if (log.isDebugEnabled()) {
                log.debug("No destination URLs configured for resident IdP in tenant: " + tenantDomain + ". Resolved " +
                        "default destination URL: " + destinationURL);
            }
        }

        return destinationURLs;
    }

    public static void doBootstrap() {
        if (!isBootStrapped) {
            try {
                SAMLInitializer.doBootstrap();
                isBootStrapped = true;
            } catch (InitializationException e) {
                log.error("Error in bootstrapping the OpenSAML3 library", e);
            }
        }
    }

    /**
     * Sign the SAML Assertion
     *
     * @param response
     * @param signatureAlgorithm
     * @param digestAlgorithm
     * @param cred
     * @return
     * @throws IdentityException
     */
    public static Assertion setSignature(Assertion response, String signatureAlgorithm, String digestAlgorithm,
                                         X509Credential cred) throws IdentityException {

        return (Assertion) doSetSignature(response, signatureAlgorithm, digestAlgorithm, cred);
    }

    /**
     * Sign the SAML Response message
     *
     * @param response
     * @param signatureAlgorithm
     * @param digestAlgorithm
     * @param cred
     * @return
     * @throws IdentityException
     */
    public static Response setSignature(Response response, String signatureAlgorithm, String digestAlgorithm,
                                        X509Credential cred) throws IdentityException {

        return (Response) doSetSignature(response, signatureAlgorithm, digestAlgorithm, cred);
    }

    /**
     * Sign the SAML LogoutResponse message
     *
     * @param response
     * @param signatureAlgorithm
     * @param digestAlgorithm
     * @param cred
     * @return
     * @throws IdentityException
     */
    public static LogoutResponse setSignature(LogoutResponse response, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentityException {

        return (LogoutResponse) doSetSignature(response, signatureAlgorithm, digestAlgorithm, cred);
    }

    /**
     *  Sign SAML Logout Request message
     *
     * @param request
     * @param signatureAlgorithm
     * @param digestAlgorithm
     * @param cred
     * @return
     * @throws IdentityException
     */
    public static LogoutRequest setSignature(LogoutRequest request, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentityException {

        return (LogoutRequest) doSetSignature(request, signatureAlgorithm, digestAlgorithm, cred);
    }

    /**
     * Sign SAML2 Artifact Response.
     *
     * @param request            ArtifactResponse object to be signed.
     * @param signatureAlgorithm Signature algorithm.
     * @param digestAlgorithm    Digest algorithm.
     * @param cred               X509 Credential.
     * @return Signed Artifact Response object.
     * @throws IdentityException
     */
    public static ArtifactResponse setSignature(ArtifactResponse request, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentityException {

        return (ArtifactResponse) doSetSignature(request, signatureAlgorithm, digestAlgorithm, cred);
    }

    /**
     * Generic method to sign SAML Logout Request
     *
     * @param request
     * @param signatureAlgorithm
     * @param digestAlgorithm
     * @param cred
     * @return
     * @throws IdentityException
     */
    private static SignableXMLObject doSetSignature(SignableXMLObject request, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentityException {

        doBootstrap();
        try {
            synchronized (Runtime.getRuntime().getClass()) {
                ssoSigner = (SSOSigner) Class.forName(IdentityUtil.getProperty(
                        SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME).trim()).newInstance();
                ssoSigner.init();
            }

            return ssoSigner.setSignature(request, signatureAlgorithm, digestAlgorithm, cred);

        } catch (ClassNotFoundException e) {
            throw IdentityException.error("Class not found: "
                    + IdentityUtil.getProperty(SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME), e);
        } catch (InstantiationException e) {
            throw IdentityException.error("Error while instantiating class: "
                    + IdentityUtil.getProperty(SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME), e);
        } catch (IllegalAccessException e) {
            throw IdentityException.error("Illegal access to class: "
                    + IdentityUtil.getProperty(SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME), e);
        } catch (Exception e) {
            throw IdentityException.error("Error while signing the XML object.", e);
        }
    }

    @Deprecated
    public static EncryptedAssertion setEncryptedAssertion(Assertion assertion, String encryptionAlgorithm,
                                                           String alias, String domainName) throws IdentityException {
        doBootstrap();
        try {
            X509Credential cred = SAMLSSOUtil.getX509CredentialImplForTenant(domainName, alias);

            synchronized (Runtime.getRuntime().getClass()) {
                ssoEncrypter = (SSOEncrypter) Class.forName(IdentityUtil.getProperty(
                        "SSOService.SAMLSSOEncrypter").trim()).newInstance();
                ssoEncrypter.init();
            }
            return ssoEncrypter.doEncryptedAssertion(assertion, cred, alias, encryptionAlgorithm);
        } catch (ClassNotFoundException e) {
            throw IdentityException.error("Class not found: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOEncrypter"), e);
        } catch (InstantiationException e) {
            throw IdentityException.error("Error while instantiating class: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOEncrypter"), e);
        } catch (IllegalAccessException e) {
            throw IdentityException.error("Illegal access to class: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOEncrypter"), e);
        } catch (Exception e) {
            throw IdentityException.error("Error while signing the SAML Response message.", e);
        }
    }

    public static EncryptedAssertion setEncryptedAssertion(Assertion assertion, String assertionEncryptionAlgorithm,
                                                           String keyEncryptionAlgorithm, X509Credential cred)
            throws IdentityException {

        doBootstrap();
        try {
            synchronized (Runtime.getRuntime().getClass()) {
                ssoEncrypter = (SSOEncrypter) Class.forName(IdentityUtil.getProperty(
                        SAMLSSOConstants.SAML_SSO_ENCRYPTOR_CONFIG_PATH).trim()).newInstance();
                ssoEncrypter.init();
            }
            return ssoEncrypter.doEncryptedAssertion(assertion, cred, null, assertionEncryptionAlgorithm,
                    keyEncryptionAlgorithm);
        } catch (ClassNotFoundException e) {
            throw IdentityException.error("Class not found: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOEncrypter"), e);
        } catch (InstantiationException e) {
            throw IdentityException.error("Error while instantiating class: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOEncrypter"), e);
        } catch (IllegalAccessException e) {
            throw IdentityException.error("Illegal access to class: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOEncrypter"), e);
        } catch (Exception e) {
            throw IdentityException.error("Error while signing the SAML Response message.", e);
        }
    }

    @Deprecated
    public static EncryptedAssertion setEncryptedAssertion(Assertion assertion, String assertionEncryptionAlgorithm,
                                                           String keyEncryptionAlgorithm, String alias, String
                                                                   domainName) throws IdentityException {

        X509Credential cred = SAMLSSOUtil.getX509CredentialImplForTenant(domainName, alias);
        return setEncryptedAssertion(assertion, assertionEncryptionAlgorithm, keyEncryptionAlgorithm, cred);
    }

    public static Assertion buildSAMLAssertion(SAMLSSOAuthnReqDTO authReqDTO, DateTime notOnOrAfter,
                                               String sessionId) throws IdentityException {

        doBootstrap();
        String assertionBuilderClass;
        try {
            assertionBuilderClass = IdentityUtil.getProperty("SSOService.SAMLSSOAssertionBuilder").trim();
            if (StringUtils.isBlank(assertionBuilderClass)) {
                assertionBuilderClass = DefaultAssertionBuilder;
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("SAMLSSOAssertionBuilder configuration is set to default builder ", e);
            }
            assertionBuilderClass = DefaultAssertionBuilder;
        }

        try {

            synchronized (Runtime.getRuntime().getClass()) {
                samlAssertionBuilder = (SAMLAssertionBuilder) Class.forName(assertionBuilderClass).newInstance();
                samlAssertionBuilder.init();
            }
            return samlAssertionBuilder.buildAssertion(authReqDTO, notOnOrAfter, sessionId);

        } catch (ClassNotFoundException e) {
            throw IdentityException.error("Class not found: "
                    + assertionBuilderClass, e);
        } catch (InstantiationException e) {
            throw IdentityException.error("Error while instantiating class: "
                    + assertionBuilderClass, e);
        } catch (IllegalAccessException e) {
            throw IdentityException.error("Illegal access to class: "
                    + assertionBuilderClass, e);
        } catch (Exception e) {
            throw IdentityException.error("Error while building the saml assertion", e);
        }
    }

    public static String createID() {

        SecureRandomIdentifierGenerationStrategy generator = new SecureRandomIdentifierGenerationStrategy();
        return generator.generateIdentifier();

    }

    /**
     * Generate the key store name from the domain name
     *
     * @param tenantDomain tenant domain name
     * @return key store file name
     */
    public static String generateKSNameFromDomainName(String tenantDomain) {

        return KeystoreUtils.getKeyStoreFileLocation(tenantDomain);
    }

    /**
     * Get the X509CredentialImpl object for a particular tenant
     *
     * @param tenantDomain
     * @param alias
     * @return X509CredentialImpl object containing the public certificate of
     * that tenant
     * @throws org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException Error when creating X509CredentialImpl object
     */
    public static X509CredentialImpl getX509CredentialImplForTenant(String tenantDomain, String alias)
            throws IdentitySAML2SSOException {

        if (tenantDomain == null || tenantDomain.trim().isEmpty() || alias == null || alias.trim().isEmpty()) {
            throw new IllegalArgumentException("Invalid parameters; domain name : " + tenantDomain + ", " +
                    "alias : " + alias);
        }
        int tenantId;
        try {
            tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error getting the tenant ID for the tenant domain : " + tenantDomain;
            throw new IdentitySAML2SSOException(errorMsg, e);
        }

        KeyStoreManager keyStoreManager;
        // get an instance of the corresponding Key Store Manager instance
        keyStoreManager = KeyStoreManager.getInstance(tenantId);

        X509CredentialImpl credentialImpl = null;
        KeyStore keyStore;

        try {
            if (tenantId != -1234) {// for tenants, load private key from their generated key store
                try {
                    FrameworkUtils.startTenantFlow(tenantDomain);
                    keyStore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
                } finally {
                    FrameworkUtils.endTenantFlow();
                }
            } else { // for super tenant, load the default pub. cert using the
                // config. in carbon.xml
                keyStore = keyStoreManager.getPrimaryKeyStore();
            }
            java.security.cert.X509Certificate cert =
                    (java.security.cert.X509Certificate) keyStore.getCertificate(alias);
            credentialImpl = new X509CredentialImpl(cert);

        } catch (Exception e) {
            String errorMsg = "Error instantiating an X509CredentialImpl object for the public certificate of " + tenantDomain;
            throw new IdentitySAML2SSOException(errorMsg, e);
        }
        return credentialImpl;
    }

    /**
     *
     * @deprecated Use {@link #validateLogoutRequestSignature(LogoutRequest, X509Certificate, String)} instead.
     *
     * Validates the request message's signature. Validates the signature of
     * both HTTP POST Binding and HTTP Redirect Binding.
     *
     * @param authnReqDTO
     * @return
     */
    @Deprecated
    public static boolean validateAuthnRequestSignature(SAMLSSOAuthnReqDTO authnReqDTO) {

        if (log.isDebugEnabled()) {
            log.debug("Validating SAML Request signature");
        }

        String domainName = authnReqDTO.getTenantDomain();
        if (authnReqDTO.isStratosDeployment()) {
            domainName = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        String alias = authnReqDTO.getCertAlias();
        RequestAbstractType request = null;

        // Check whether certificate is expired or not before the signature validation
        try {
            SAMLSSOServiceProviderDO serviceProviderConfigs = getServiceProviderConfig(domainName,
                    authnReqDTO.getIssuer());
            // Check whether certificate is expired or not before the signature validation.
            if (isSpCertificateExpiryValidationEnabled()) {
                if (isCertificateExpired(serviceProviderConfigs.getX509Certificate())) return false;
            }
        } catch (IdentityException e) {
            log.error("A Service Provider with the Issuer '" + authnReqDTO.getIssuer()+ "' is not " +
                    "registered. Service Provider should be registered in advance.");
            return false;
        }

        try {
            String decodedReq = null;

            if (authnReqDTO.getQueryString() != null) {
                decodedReq = SAMLSSOUtil.decode(authnReqDTO.getRequestMessageString());
            } else {
                decodedReq = SAMLSSOUtil.decodeForPost(authnReqDTO.getRequestMessageString());
            }

            request = (RequestAbstractType) SAMLSSOUtil.unmarshall(decodedReq);
        } catch (IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Signature Validation failed for the SAMLRequest : Failed to unmarshall the SAML Assertion", e);
            }
        }

        try {
            if (authnReqDTO.getQueryString() != null) {
                // DEFLATE signature in Redirect Binding
                return validateDeflateSignature(authnReqDTO.getQueryString(), authnReqDTO.getIssuer(), alias,
                        domainName);
            } else {
                // XML signature in SAML Request message for POST Binding
                return validateXMLSignature(request, alias, domainName);
            }
        } catch (IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Signature Validation failed for the SAMLRequest : Failed to validate the SAML Assertion", e);
            }
            return false;
        }
    }

    /**
     * Validates the request message's signature. Validates the signature of
     * both HTTP POST Binding and HTTP Redirect Binding against the given certificate.
     *
     * @param authnReqDTO The authentication request.
     * @param certificate The certificate which used for validation.
     * @return
     */
    public static boolean validateAuthnRequestSignature(SAMLSSOAuthnReqDTO authnReqDTO, X509Certificate certificate) {

        if (log.isDebugEnabled()) {
            log.debug("Validating SAML Request signature");
        }

        RequestAbstractType request = null;
        try {
            String decodedReq = null;

            if (authnReqDTO.getQueryString() != null) {
                decodedReq = SAMLSSOUtil.decode(authnReqDTO.getRequestMessageString());
            } else {
                decodedReq = SAMLSSOUtil.decodeForPost(authnReqDTO.getRequestMessageString());
            }

            request = (RequestAbstractType) SAMLSSOUtil.unmarshall(decodedReq);
        } catch (IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Signature Validation failed for the SAMLRequest : " +
                        "Failed to unmarshall the SAML Assertion", e);
            }
        }

        try {

            String issuer = authnReqDTO.getIssuer();

            if (authnReqDTO.getQueryString() != null) {
                // DEFLATE signature in Redirect Binding
                return validateDeflateSignature(authnReqDTO.getQueryString(), issuer, certificate);
            } else {
                // XML signature in SAML Request message for POST Binding
                return validateXMLSignature(request, certificate);
            }
        } catch (IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Signature Validation failed for the SAMLRequest : " +
                        "Failed to validate the SAML Assertion", e);
            }
            return false;
        }
    }


    /**
     *
     * @deprecated Use {@link #validateLogoutRequestSignature(LogoutRequest, X509Certificate, String)} instead.
     *
     * Validates the signature of the LogoutRequest message.
     * TODO : for stratos deployment, super tenant key should be used
     * @param logoutRequest
     * @param alias
     * @param subject
     * @param queryString
     * @return
     * @throws IdentityException
     */
    @Deprecated
    public static boolean validateLogoutRequestSignature(LogoutRequest logoutRequest, String alias,
                                                         String subject, String queryString) throws IdentityException {

        String domainName = getTenantDomainFromThreadLocal();
        if (queryString != null) {
            return validateDeflateSignature(queryString, logoutRequest.getIssuer().getValue(), alias, domainName);
        } else {
            return validateXMLSignature(logoutRequest, alias, domainName);
        }
    }

    /**
     * Validate the signature of the LogoutRequest message against the given certificate.
     * @param logoutRequest The logout request object if available.
     * @param queryString The request query string if available.
     * @param certificate The certificate which is used for signature validation.
     * @return
     * @throws IdentityException
     */
    public static boolean validateLogoutRequestSignature(LogoutRequest logoutRequest, X509Certificate certificate,
                                                         String queryString) throws IdentityException {


        String issuer = logoutRequest.getIssuer().getValue();

        if (queryString != null && queryString.contains(SAML_REQUEST)) {
            return validateDeflateSignature(queryString, issuer, certificate);
        } else {
            return validateXMLSignature(logoutRequest, certificate);
        }
    }

    /**
     *
     * @deprecated Use {@link #validateDeflateSignature(String, String, X509Certificate)} instead.
     *
     * Signature validation for HTTP Redirect Binding
     * @param queryString
     * @param issuer
     * @param alias
     * @param domainName
     * @return
     * @throws IdentityException
     */
    @Deprecated
    public static boolean validateDeflateSignature(String queryString, String issuer,
                                                   String alias, String domainName) throws IdentityException {
        try {

            synchronized (Runtime.getRuntime().getClass()) {
                samlHTTPRedirectSignatureValidator = (SAML2HTTPRedirectSignatureValidator) Class.forName(IdentityUtil.getProperty(
                        SAMLSSOConstants.SAML2_HTTP_REDIRECT_SIGNATURE_VALIDATOR_CLASS_NAME).trim()).newInstance();
                samlHTTPRedirectSignatureValidator.init();
            }

            return samlHTTPRedirectSignatureValidator.validateSignature(queryString, issuer,
                    alias, domainName);

        } catch (SecurityException e) {
            log.error("Error validating deflate signature", e);
            return false;
        } catch (IdentitySAML2SSOException e) {
            log.warn("Signature validation failed for the SAML Message : Failed to construct the X509CredentialImpl for the alias " +
                    alias, e);
            return false;
        } catch (ClassNotFoundException e) {
            throw IdentityException.error("Class not found: "
                    + IdentityUtil.getProperty(SAMLSSOConstants.SAML2_HTTP_REDIRECT_SIGNATURE_VALIDATOR_CLASS_NAME), e);
        } catch (InstantiationException e) {
            throw IdentityException.error("Error while instantiating class: "
                    + IdentityUtil.getProperty(SAMLSSOConstants.SAML2_HTTP_REDIRECT_SIGNATURE_VALIDATOR_CLASS_NAME), e);
        } catch (IllegalAccessException e) {
            throw IdentityException.error("Illegal access to class: "
                    + IdentityUtil.getProperty(SAMLSSOConstants.SAML2_HTTP_REDIRECT_SIGNATURE_VALIDATOR_CLASS_NAME), e);
        }
    }

    /**
     * Validates the signature of the SAML requests sent with HTTP Redirect Binding against the given certificate.
     *
     * @param queryString SAML request
     * @param issuer      Issuer of the SAML request
     * @param certificate The certificate which is used for signature validation.
     * @return true if the signature is valid, false otherwise.
     * @throws IdentityException if something goes wrong during signature validation.
     */
    public static boolean validateDeflateSignature(String queryString, String issuer,
                                                   java.security.cert.X509Certificate certificate)
            throws IdentityException {
        try {

            synchronized (Runtime.getRuntime().getClass()) {
                samlHTTPRedirectSignatureValidator = (SAML2HTTPRedirectSignatureValidator) Class.forName(
                        IdentityUtil.getProperty(SAMLSSOConstants
                                .SAML2_HTTP_REDIRECT_SIGNATURE_VALIDATOR_CLASS_NAME).trim()).newInstance();
                samlHTTPRedirectSignatureValidator.init();
            }

            return samlHTTPRedirectSignatureValidator.validateSignature(queryString, issuer, certificate);

        } catch (SecurityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error validating deflate signature for the issuer: " + issuer, e);
            }
            return false;
        } catch (ClassNotFoundException e) {
            throw IdentityException.error("Class not found: "
                    + IdentityUtil.getProperty(SAMLSSOConstants.SAML2_HTTP_REDIRECT_SIGNATURE_VALIDATOR_CLASS_NAME), e);
        } catch (InstantiationException e) {
            throw IdentityException.error("Error while instantiating class: "
                    + IdentityUtil.getProperty(SAMLSSOConstants.SAML2_HTTP_REDIRECT_SIGNATURE_VALIDATOR_CLASS_NAME), e);
        } catch (IllegalAccessException e) {
            throw IdentityException.error("Illegal access to class: "
                    + IdentityUtil.getProperty(SAMLSSOConstants.SAML2_HTTP_REDIRECT_SIGNATURE_VALIDATOR_CLASS_NAME), e);
        }
    }

    /**
     *
     * @deprecated Use {@link #validateXMLSignature(RequestAbstractType, X509Certificate)} instead.
     *
     * Validate the signature of an assertion
     *
     * @param request    SAML Assertion, this could be either a SAML Request or a
     *                   LogoutRequest
     * @param alias      Certificate alias against which the signature is validated.
     * @param domainName domain name of the subject
     * @return true, if the signature is valid.
     */
    @Deprecated
    public static boolean validateXMLSignature(RequestAbstractType request, String alias,
                                               String domainName) throws IdentityException {

        return validateXMLSignature((SignableXMLObject) request, alias, domainName);
    }

    /**
     * Validate the signature of a Signable XML Object.
     * @param request Signable XML Object.
     * @param alias Certificate alias.
     * @param domainName Tenant domain name.
     * @return Is this a valid signature.
     * @throws IdentityException Error trying to get the certificate.
     */
    public static boolean validateXMLSignature(SignableXMLObject request, String alias,
                                               String domainName) throws IdentityException {
        boolean isSignatureValid = false;

        if (request.getSignature() != null) {
            try {
                X509Credential cred = SAMLSSOUtil.getX509CredentialImplForTenant(domainName, alias);

                synchronized (Runtime.getRuntime().getClass()) {
                    ssoSigner = (SSOSigner) Class.forName(IdentityUtil.getProperty(
                            SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME).trim()).newInstance();
                    ssoSigner.init();
                }

                // This is to give backward compatibility. The overloaded method in the DefaultSSOSigner is added later.
                // Since we cannot add the overload to the interface, we can use this method only if this is an instance
                // of DefaultSSOSigner. TODO: Change this behaviour when we can do API changes.
                if (ssoSigner instanceof DefaultSSOSigner) {
                    return ((DefaultSSOSigner) ssoSigner).validateXMLSignature(request, cred, alias);
                } else {
                    if (request instanceof RequestAbstractType) {
                        return ssoSigner.validateXMLSignature((RequestAbstractType) request, cred, alias);
                    } else {
                        throw new IdentityException("Invalid request object type: " + request.getClass());
                    }
                }
            } catch (IdentitySAML2SSOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature validation failed for the SAML Message : Failed to construct the " +
                            "X509CredentialImpl for the alias " + alias, e);
                }
            } catch (ClassNotFoundException e) {
                throw IdentityException.error("Class not found: "
                        + IdentityUtil.getProperty(SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME), e);
            } catch (InstantiationException e) {
                throw IdentityException.error("Error while instantiating class: "
                        + IdentityUtil.getProperty(SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME), e);
            } catch (IllegalAccessException e) {
                throw IdentityException.error("Illegal access to class: "
                        + IdentityUtil.getProperty(SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME), e);
            }
        }
        return isSignatureValid;
    }

    /**
     * Validates the signature of an assertion against the given certificate.
     *
     * @param request    SAML Assertion, this could be either a SAML Request or a LogoutRequest
     * @param certificate The certificate which is used for signature validation.
     * @return true, if the signature is valid.
     * @throws IdentityException if something goes wrong during signature validation.
     */
    public static boolean validateXMLSignature(RequestAbstractType request,
                                               java.security.cert.X509Certificate certificate) throws IdentityException {

        boolean isSignatureValid = false;

        if (request.getSignature() != null) {
            try {
                X509Credential cred = new X509CredentialImpl(certificate);

                synchronized (Runtime.getRuntime().getClass()) {
                    ssoSigner = (SSOSigner) Class.forName(IdentityUtil.getProperty(
                            SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME).trim()).newInstance();
                    ssoSigner.init();
                }

                return ssoSigner.validateXMLSignature(request, cred, null);
            } catch (IdentityException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Validation Failed for the SAML Assertion : Signature is invalid.", e);
                }
            } catch (ClassNotFoundException e) {
                throw IdentityException.error("Class not found: "
                        + IdentityUtil.getProperty(SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME), e);
            } catch (InstantiationException e) {
                throw IdentityException.error("Error while instantiating class: "
                        + IdentityUtil.getProperty(SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME), e);
            } catch (IllegalAccessException e) {
                throw IdentityException.error("Illegal access to class: "
                        + IdentityUtil.getProperty(SAMLSSOConstants.SAMLSSO_SIGNER_CLASS_NAME), e);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while validating XML signature.", e);
                }
            }
        }
        return isSignatureValid;
    }

    /**
     * Return a Array of Claims containing requested attributes and values
     *
     * @param authnReqDTO
     * @return Map with attributes and values
     * @throws IdentityException
     */
    public static Map<String, String> getAttributes(SAMLSSOAuthnReqDTO authnReqDTO) throws IdentityException {

        int index = 0;

        // trying to get the Service Provider Configurations
        SSOServiceProviderConfigManager spConfigManager =
                SSOServiceProviderConfigManager.getInstance();
        SAMLSSOServiceProviderDO spDO = spConfigManager.getServiceProvider(authnReqDTO.getIssuer());

        if (spDO == null) {

            spDO = getSAMLServiceProviderFromRegistry(authnReqDTO.getIssuer(), authnReqDTO.getTenantDomain());
        }

        if (!authnReqDTO.isIdPInitSSOEnabled()) {

            if ( authnReqDTO.getAttributeConsumingServiceIndex() == 0) {
                //SP has not provide a AttributeConsumingServiceIndex in the authnReqDTO
                if (StringUtils.isNotBlank(spDO.getAttributeConsumingServiceIndex()) && spDO
                        .isEnableAttributesByDefault()) {
                    index = Integer.parseInt(spDO.getAttributeConsumingServiceIndex());
                } else if (CollectionUtils.isEmpty(authnReqDTO.getRequestedAttributes())) {
                    return Collections.emptyMap();
                }
            } else {
                //SP has provide a AttributeConsumingServiceIndex in the authnReqDTO
                index = authnReqDTO.getAttributeConsumingServiceIndex();
            }
        } else {
            if (StringUtils.isNotBlank(spDO.getAttributeConsumingServiceIndex()) && spDO.isEnableAttributesByDefault
                    ()) {
                index = Integer.parseInt(spDO.getAttributeConsumingServiceIndex());
            } else {
                return Collections.emptyMap();
            }

        }


        /*
           IMPORTANT : checking if the consumer index in the request matches the
           given id to the SP
         */
        if (((spDO.getAttributeConsumingServiceIndex() == null ||
                "".equals(spDO.getAttributeConsumingServiceIndex())) &&
                CollectionUtils.isEmpty(authnReqDTO.getRequestedAttributes())) ||
                (index !=0 && index != Integer.parseInt(spDO.getAttributeConsumingServiceIndex()))) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid AttributeConsumingServiceIndex in AuthnRequest");
            }
            return Collections.emptyMap();
        }

        Map<String, String> claimsMap = new HashMap<String, String>();
        if (authnReqDTO.getUser().getUserAttributes() != null) {
            for (Map.Entry<ClaimMapping, String> entry : authnReqDTO.getUser().getUserAttributes().entrySet()) {
                claimsMap.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
            }
        }
        return claimsMap;
    }


    /**
     * build the error response
     *
     * @param id
     * @param statusCodes
     * @param statusMsg
     * @return decoded response
     * @throws IdentityException
     */
    public static String buildErrorResponse(String id, List<String> statusCodes, String statusMsg, String destination)
            throws IdentityException {
        ErrorResponseBuilder respBuilder = new ErrorResponseBuilder();
        Response response = respBuilder.buildResponse(id, statusCodes, statusMsg, destination);
        return SAMLSSOUtil.encode(SAMLSSOUtil.marshall(response));
    }

    /**
     * Build a deflated SAML error response.
     *
     * @param id
     * @param statusCodes
     * @param statusMsg
     * @param destination
     * @return
     * @throws IdentityException
     * @throws IOException
     */
    public static String buildCompressedErrorResponse(String id, List<String> statusCodes, String statusMsg, String
            destination) throws IdentityException, IOException {
        ErrorResponseBuilder respBuilder = new ErrorResponseBuilder();
        Response response = respBuilder.buildResponse(id, statusCodes, statusMsg, destination);
        String resp = SAMLSSOUtil.marshall(response);
        return compressResponse(resp);
    }

    public static int getSAMLResponseValidityPeriod() {
        if (StringUtils.isNotBlank(IdentityUtil.getProperty(IdentityConstants.ServerConfig.SAML_RESPONSE_VALIDITY_PERIOD))) {
            return Integer.parseInt(IdentityUtil.getProperty(
                    IdentityConstants.ServerConfig.SAML_RESPONSE_VALIDITY_PERIOD).trim());
        } else {
            return 5;
        }
    }

    /**
     * Return validity period for SAML2 artifacts defined in identity.xml file.
     * @return Validity period in minutes.
     */
    public static int getSAML2ArtifactValidityPeriod() {
        if (StringUtils.isNotBlank(IdentityUtil.getProperty(IdentityConstants.ServerConfig.SAML2_ARTIFACT_VALIDITY_PERIOD))) {
            return Integer.parseInt(IdentityUtil.getProperty(
                    IdentityConstants.ServerConfig.SAML2_ARTIFACT_VALIDITY_PERIOD).trim());
        } else {
            return 5;
        }
    }

    public static int getSingleLogoutRetryCount() {
        return singleLogoutRetryCount;
    }

    public static void setSingleLogoutRetryCount(int singleLogoutRetryCount) {
        SAMLSSOUtil.singleLogoutRetryCount = singleLogoutRetryCount;
    }

    public static long getSingleLogoutRetryInterval() {
        return singleLogoutRetryInterval;
    }

    public static void setSingleLogoutRetryInterval(long singleLogoutRetryInterval) {
        SAMLSSOUtil.singleLogoutRetryInterval = singleLogoutRetryInterval;
    }

    public static ResponseBuilder getResponseBuilder() {
        if (responseBuilderClassName == null || "".equals(responseBuilderClassName)) {
            return new DefaultResponseBuilder();
        } else {
            try {
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(responseBuilderClassName);
                return (ResponseBuilder) clazz.newInstance();

            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                log.error("Error while instantiating the SAMLResponseBuilder ", e);
            }
        }
        return null;
    }

    public static void setResponseBuilder(String responseBuilder) {
        responseBuilderClassName = responseBuilder;
    }

    /**
     * This check if the status code is 2XX, check value between 200 and 300
     *
     * @param status
     * @return
     */
    public static boolean isHttpSuccessStatusCode(int status) {
        return status >= 200 && status < 300;
    }

    public static boolean isHttpRedirectStatusCode(int status) {
        return status == 302 || status == 303;
    }

    public static String getUserNameFromOpenID(String openid) throws IdentityException {
        String caller = null;
        String path = null;
        URI uri = null;
        String contextPath = "/openid/";

        try {
            uri = new URI(openid);
            path = uri.getPath();
        } catch (URISyntaxException e) {
            throw IdentityException.error("Invalid OpenID", e);
        }
        caller = path.substring(path.indexOf(contextPath) + contextPath.length(), path.length());
        return caller;
    }

    /**
     * Find the OpenID corresponding to the given user name.
     *
     * @param userName User name
     * @return OpenID corresponding the given user name.
     * @throws org.wso2.carbon.identity.base.IdentityException
     */
    public static String getOpenID(String userName) throws IdentityException {
        return generateOpenID(userName);
    }

    /**
     * Generate OpenID for a given user.
     *
     * @param user User
     * @return Generated OpenID
     * @throws org.wso2.carbon.identity.base.IdentityException
     */
    public static String generateOpenID(String user) throws IdentityException {
        String openIDUserUrl = null;
        String openID = null;
        URI uri = null;
        URL url = null;
        openIDUserUrl = IdentityUtil.getProperty(IdentityConstants.ServerConfig.OPENID_USER_PATTERN);
        user = normalizeUrlEncoding(user);
        openID = openIDUserUrl + user;
        try {
            uri = new URI(openID);
        } catch (URISyntaxException e) {
            throw IdentityException.error("Invalid OpenID URL :" + openID, e);
        }
        try {
            url = uri.normalize().toURL();
            if (url.getQuery() != null || url.getRef() != null) {
                throw IdentityException.error("Invalid user name for OpenID :" + openID);
            }
        } catch (MalformedURLException e) {
            throw IdentityException.error("Malformed OpenID URL :" + openID, e);
        }
        openID = url.toString();
        return openID;
    }

    private static String normalizeUrlEncoding(String text) {

        if (text == null)
            return null;

        int len = text.length();
        StringBuilder normalized = new StringBuilder(len);

        for (int i = 0; i < len; i++) {
            char current = text.charAt(i);
            if (current == '%' && i < len - 2) {
                String percentCode = text.substring(i, i + 3).toUpperCase();
                try {
                    String str = URLDecoder.decode(percentCode, "ISO-8859-1");
                    char chr = str.charAt(0);
                    if (UNRESERVED_CHARACTERS.contains(Character.valueOf(chr)))
                        normalized.append(chr);
                    else
                        normalized.append(percentCode);
                } catch (UnsupportedEncodingException e) {
                    normalized.append(percentCode);
                    if (log.isDebugEnabled()) {
                        log.debug("Unsupported Encoding exception while decoding percent code.", e);
                    }
                }
                i += 2;
            } else {
                normalized.append(current);
            }
        }
        return normalized.toString();
    }

    /**
     * @deprecated This method was deprecated to move saml caches to the tenant space.
     * Use {@link #removeSession(String, String, String)}  )} instead.
     */
    @Deprecated
    public static void removeSession(String sessionId, String issuer) {

        removeSession(sessionId, issuer, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     *  Removes the session.
     *
     * @param sessionId          Session id.
     * @param issuer             Issuer.
     * @param loginTenantDomain  Login tenant Domain.
     */
    public static void removeSession(String sessionId, String issuer, String loginTenantDomain) {

        SSOSessionPersistenceManager ssoSessionPersistenceManager = SSOSessionPersistenceManager
                .getPersistenceManager();
        ssoSessionPersistenceManager.removeSession(sessionId, issuer, loginTenantDomain);
    }

    public static void setTenantDomainInThreadLocal(String tenantDomain) throws UserStoreException, IdentityException {

        tenantDomain = validateTenantDomain(tenantDomain);
        if (tenantDomain != null) {
            SAMLSSOUtil.tenantDomainInThreadLocal.set(tenantDomain);
        }
    }

    public static String getTenantDomainFromThreadLocal() {

        if (SAMLSSOUtil.tenantDomainInThreadLocal == null) {
            // this is the default behavior.
            return null;
        }
        return (String) SAMLSSOUtil.tenantDomainInThreadLocal.get();
    }

    public static void removeTenantDomainFromThreadLocal() {
        SAMLSSOUtil.tenantDomainInThreadLocal.remove();
    }

    public static String getIssuerWithQualifierInThreadLocal() {

        if (SAMLSSOUtil.issuerWithQualifierInThreadLocal == null) {
            // This is the default behavior.
            return null;
        }
        // This is the behaviour when an issuer qualifier is provided.
        return (String) SAMLSSOUtil.issuerWithQualifierInThreadLocal.get();
    }

    /**
     * Issuer with qualifier is saved to a ThreadLocal because it is needed to identify the SP
     * to get the IdpEntityIDAlias to override IdP Entity ID when sending SAML respnse to SP.
     *
     * @param issuerWithQualifierInThreadLocal
     */
    public static void setIssuerWithQualifierInThreadLocal(String issuerWithQualifierInThreadLocal) {

        if (issuerWithQualifierInThreadLocal != null) {
            SAMLSSOUtil.issuerWithQualifierInThreadLocal.set(issuerWithQualifierInThreadLocal);
        }
    }

    /**
     * Remove IssuerWithQualifierInThreadLocal when finishing the whole process.
     */
    public static void removeIssuerWithQualifierInThreadLocal() {

        SAMLSSOUtil.issuerWithQualifierInThreadLocal.remove();
    }

    public static String validateTenantDomain(String tenantDomain) throws UserStoreException, IdentityException {

        if (tenantDomain != null && !tenantDomain.trim().isEmpty() && !"null".equalsIgnoreCase(tenantDomain.trim())) {
            int tenantID = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
            if (tenantID == -1) {
                String message = "Invalid tenant domain : " + tenantDomain;
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }
                throw IdentityException.error(message);
            } else {
                return tenantDomain;
            }
        }
        return null;
    }

    /**
     * Initialize the SPInitSSOAuthnRequestValidator
     * @param authnRequest AuthnRequest request
     * @param queryString encorded saml request
     * @return SSOAuthnRequestValidator
     */
    public static SSOAuthnRequestValidator getSPInitSSOAuthnRequestValidator(AuthnRequest authnRequest,
                                                                             String queryString)  {
        if (StringUtils.isEmpty(sPInitSSOAuthnRequestValidatorClassName)) {
            try {
                return new SPInitSSOAuthnRequestValidator(authnRequest, queryString);
            } catch (IdentityException e) {
                log.error("Error while instantiating the SPInitSSOAuthnRequestValidator ", e);
            }
        } else {
            try {
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(sPInitSSOAuthnRequestValidatorClassName);
                return (SSOAuthnRequestValidator) clazz.getDeclaredConstructor(AuthnRequest.class, String.class)
                        .newInstance(authnRequest, queryString);
            } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
                log.error("Error while instantiating the SPInitSSOAuthnRequestValidator ", e);
            } catch (NoSuchMethodException e) {
                log.error("SP initiated authentication request validation class in run time does not have proper" +
                        "constructors defined.");
            } catch (InvocationTargetException e) {
                log.error("Error in creating an instance of the class: " + sPInitSSOAuthnRequestValidatorClassName);
            }
        }
        return null;
    }

    /**
     * build the error response
     *
     * @param status
     * @param message
     * @return decoded response
     * @throws org.wso2.carbon.identity.base.IdentityException
     */
    public static String buildErrorResponse(String status, String message, String destination)
            throws IdentityException, IOException {

        ErrorResponseBuilder respBuilder = new ErrorResponseBuilder();
        List<String> statusCodeList = new ArrayList<String>();
        statusCodeList.add(status);
        Response response = respBuilder.buildResponse(null, statusCodeList, message, destination);
        String resp = SAMLSSOUtil.marshall(response);
        return compressResponse(resp);
    }

    /**
     * Compresses the response String
     *
     * @param response
     * @return
     * @throws IOException
     */
    public static String compressResponse(String response) throws IOException {

        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
        try {
            deflaterOutputStream.write(response.getBytes(StandardCharsets.UTF_8));
        } finally {
            deflaterOutputStream.close();
        }
        return Base64Support.encode(byteArrayOutputStream.toByteArray(), Base64Support.UNCHUNKED);
    }

    public static String getNotificationEndpoint(){

        try {
            return resolveUrl(SAMLSSOConstants.NOTIFICATION_ENDPOINT, IdentityUtil.getProperty(IdentityConstants.ServerConfig
                    .NOTIFICATION_ENDPOINT));
        } catch (URLBuilderException e) {
            throw new IdentityRuntimeException("Error while resolving default endpoint that handles SAML error " +
                    "notifications", e);
        }
    }

    public static String getDefaultLogoutEndpoint() {

        try {
            return resolveUrl(SAMLSSOConstants.DEFAULT_LOGOUT_ENDPOINT, IdentityUtil.getProperty(IdentityConstants.ServerConfig
                    .DEFAULT_LOGOUT_ENDPOINT));
        } catch (URLBuilderException e) {
            throw new IdentityRuntimeException("Error while resolving the default endpoint that handles SAML logout ", e);
        }
    }

    public static boolean isSAMLIssuerExists(String issuerName, String tenantDomain) throws IdentitySAML2SSOException {

        SSOServiceProviderConfigManager stratosIdpConfigManager = SSOServiceProviderConfigManager.getInstance();
        SAMLSSOServiceProviderDO serviceProvider = stratosIdpConfigManager.getServiceProvider(issuerName);
        if (serviceProvider != null) {
            return true;
        }

        int tenantId;
        if (StringUtils.isBlank(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            tenantId = MultitenantConstants.SUPER_TENANT_ID;
        } else {
            try {
                tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            } catch (UserStoreException e) {
                throw new IdentitySAML2SSOException("Error occurred while retrieving tenant id for the domain : " +
                        tenantDomain, e);
            }
        }

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            privilegedCarbonContext.setTenantId(tenantId);
            privilegedCarbonContext.setTenantDomain(tenantDomain);

            IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            return IdentitySAMLSSOServiceComponentHolder.getInstance().getSAMLSSOServiceProviderManager()
                    .isServiceProviderExists(issuerName, tenantId);
        } catch (IdentityException e) {
            throw new IdentitySAML2SSOException("Error occurred while validating existence of SAML service provider " +
                    "'" + issuerName + "' in the tenant domain '" + tenantDomain + "'");
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    /**
     * Check whether an SP with an "Issuer with qualifier" exists and whether issuer value without qualifier is similar
     * to the Issuer of SAML request.
     *
     * @param issuerName          Issuer of SAML request.
     * @param issuerWithQualifier Issuer value saved in the registry.
     * @param tenantDomain
     * @return true, if a SAML SP exists in the registry with the issuer value similar to "issuerWithQualifier"
     * and the SAML request's issuer is equal to the issuer without qualifier.
     */
    public static boolean isValidSAMLIssuer(String issuerName, String issuerWithQualifier, String tenantDomain)
            throws IdentitySAML2SSOException {

        if (isSAMLIssuerExists(issuerWithQualifier, tenantDomain)) {
            return issuerName.equals(getIssuerWithoutQualifier(issuerWithQualifier));
        }
        return false;
    }

    public static boolean validateACS(String tenantDomain, String issuerName, String requestedACSUrl) throws
            IdentityException {
        SSOServiceProviderConfigManager stratosIdpConfigManager = SSOServiceProviderConfigManager.getInstance();
        SAMLSSOServiceProviderDO serviceProvider = stratosIdpConfigManager.getServiceProvider(issuerName);
        if (serviceProvider != null) {
            return true;
        }

        int tenantId;
        if (StringUtils.isBlank(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            tenantId = MultitenantConstants.SUPER_TENANT_ID;
        } else {
            try {
                tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            } catch (UserStoreException e) {
                throw new IdentitySAML2SSOException("Error occurred while retrieving tenant id for the domain : " +
                        tenantDomain, e);
            }
        }

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            privilegedCarbonContext.setTenantId(tenantId);
            privilegedCarbonContext.setTenantDomain(tenantDomain);

            SAMLSSOServiceProviderDO spDO = IdentitySAMLSSOServiceComponentHolder.getInstance()
                    .getSAMLSSOServiceProviderManager().getServiceProvider(issuerName, tenantId);
            if (StringUtils.isBlank(requestedACSUrl) || !spDO.getAssertionConsumerUrlList().contains
                    (requestedACSUrl)) {
                String msg = "ALERT: Invalid Assertion Consumer URL value '" + requestedACSUrl + "' in the " +
                        "AuthnRequest message from  the issuer '" + spDO.getIssuer() +
                        "'. Possibly " + "an attempt for a spoofing attack";
                log.error(msg);
                return false;
            } else {
                return true;
            }
        } catch (IdentityException e) {
            throw new IdentitySAML2SSOException("Error occurred while validating existence of SAML service provider " +
                    "'" + issuerName + "' in the tenant domain '" + tenantDomain + "'");
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }

    }

    /**
     * Get SP initiated request validator.
     *
     * @param authnRequest authentication request
     * @return SP initiated request validator
     */
    public static SSOAuthnRequestValidator getSPInitSSOAuthnRequestValidator(AuthnRequest authnRequest) {
        SSOAuthnRequestValidator ssoAuthnRequestValidator = null;
        try {
            if (StringUtils.isNotBlank(sPInitSSOAuthnRequestValidatorClassName)) {
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(sPInitSSOAuthnRequestValidatorClassName);
                ssoAuthnRequestValidator = (SSOAuthnRequestValidator) clazz.getDeclaredConstructor(AuthnRequest.class)
                        .newInstance(authnRequest);
            } else if(IdentityUtil.getProperty(SAMLSSOConstants.SAML_SSO_SP_REQUEST_VALIDATOR_CONFIG_PATH) != null) {
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(IdentityUtil.getProperty(SAMLSSOConstants.SAML_SSO_SP_REQUEST_VALIDATOR_CONFIG_PATH)
                                .trim());
                ssoAuthnRequestValidator = (SSOAuthnRequestValidator) clazz.getDeclaredConstructor(AuthnRequest.class)
                        .newInstance(authnRequest);
            } else {
                ssoAuthnRequestValidator = new SPInitSSOAuthnRequestValidator(authnRequest);
            }
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException | IdentityException e) {
            log.error("Error while instantiating the SPInitSSOAuthnRequestValidator ", e);
        } catch (NoSuchMethodException e) {
            log.error("SP initiated authentication request validation class in run time does not have proper" +
                    "constructors defined.");
        } catch (InvocationTargetException e) {
            log.error("Error in creating an instance of the class: " + sPInitSSOAuthnRequestValidatorClassName);
        }
        return ssoAuthnRequestValidator;
    }

    public static void setSPInitSSOAuthnRequestValidator(String sPInitSSOAuthnRequestValidator) {
        sPInitSSOAuthnRequestValidatorClassName = sPInitSSOAuthnRequestValidator;
    }


    public static SSOAuthnRequestValidator getIdPInitSSOAuthnRequestValidator(QueryParamDTO[] queryParamDTOs, String relayState) {
        if (iDPInitSSOAuthnRequestValidatorClassName == null || "".equals(iDPInitSSOAuthnRequestValidatorClassName)) {
            try {
                return new IdPInitSSOAuthnRequestValidator(queryParamDTOs, relayState);
            } catch (IdentityException e) {
                log.error("Error while instantiating the IdPInitSSOAuthnRequestValidator ", e);
            }
        } else {
            try {
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(iDPInitSSOAuthnRequestValidatorClassName);
                return (SSOAuthnRequestValidator) clazz.getDeclaredConstructor(
                        QueryParamDTO[].class, String.class).newInstance(queryParamDTOs, relayState);

            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                log.error("Error while instantiating the IdPInitSSOAuthnRequestValidator ", e);
            } catch (NoSuchMethodException e) {
                log.error("SP initiated authentication request validation class in run time does not have proper" +
                        "constructors defined.");
            } catch (InvocationTargetException e) {
                log.error("Error in creating an instance of the class: " + sPInitSSOAuthnRequestValidatorClassName);
            }
        }
        return null;
    }

    public static void setIdPInitSSOAuthnRequestValidator(String iDPInitSSOAuthnRequestValidator) {
        iDPInitSSOAuthnRequestValidatorClassName = iDPInitSSOAuthnRequestValidator;
    }

    public static void setIdPInitSSOAuthnRequestProcessor(String idPInitSSOAuthnRequestProcessor) {
    }

    public static IdPInitSSOAuthnRequestProcessor getIdPInitSSOAuthnRequestProcessor() {
        if (iDPInitSSOAuthnRequestValidatorClassName == null || "".equals(iDPInitSSOAuthnRequestValidatorClassName)) {
            return new IdPInitSSOAuthnRequestProcessor();
        } else {
            try {
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(iDPInitSSOAuthnRequestValidatorClassName);
                return (IdPInitSSOAuthnRequestProcessor) clazz.newInstance();

            } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
                log.error("Error while instantiating the IdPInitSSOAuthnRequestProcessor ", e);
            }
        }
        return null;
    }

    public static void setSPInitSSOAuthnRequestProcessor(String SPInitSSOAuthnRequestProcessor) {
        SAMLSSOUtil.sPInitSSOAuthnRequestProcessorClassName = SPInitSSOAuthnRequestProcessor;
    }

    public static SPInitSSOAuthnRequestProcessor getSPInitSSOAuthnRequestProcessor() {
        if (sPInitSSOAuthnRequestProcessorClassName == null || "".equals(sPInitSSOAuthnRequestProcessorClassName)) {
            return new SPInitSSOAuthnRequestProcessor();
        } else {
            try {
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(sPInitSSOAuthnRequestProcessorClassName);
                return (SPInitSSOAuthnRequestProcessor) clazz.newInstance();

            } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
                log.error("Error while instantiating the SPInitSSOAuthnRequestProcessor ", e);
            }
        }
        return null;
    }

    public static void setSPInitLogoutRequestProcessor(String SPInitLogoutRequestProcessor) {
        SAMLSSOUtil.sPInitLogoutRequestProcessorClassName = SPInitLogoutRequestProcessor;
    }

    public static SPInitLogoutRequestProcessor getSPInitLogoutRequestProcessor() {
        if (sPInitLogoutRequestProcessorClassName == null || "".equals(sPInitLogoutRequestProcessorClassName)) {
            return new SPInitLogoutRequestProcessor();
        } else {
            try {
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(sPInitLogoutRequestProcessorClassName);
                return (SPInitLogoutRequestProcessor) clazz.newInstance();

            } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
                log.error("Error while instantiating the SPInitLogoutRequestProcessor ", e);
            }
        }
        return null;
    }

    public static void setIdPInitLogoutRequestProcessor(String idPInitLogoutRequestProcessor) {
        SAMLSSOUtil.idPInitLogoutRequestProcessorClassName = idPInitLogoutRequestProcessor;
    }

    public static IdPInitLogoutRequestProcessor getIdPInitLogoutRequestProcessor() {
        if (idPInitLogoutRequestProcessorClassName == null || "".equals(idPInitLogoutRequestProcessorClassName)) {
            return new IdPInitLogoutRequestProcessor();
        } else {
            try {
                // Bundle class loader will cache the loaded class and returned
                // the already loaded instance, hence calling this method
                // multiple times doesn't cost.
                Class clazz = Thread.currentThread().getContextClassLoader()
                        .loadClass(idPInitLogoutRequestProcessorClassName);
                return (IdPInitLogoutRequestProcessor) clazz.newInstance();

            } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
                log.error("Error while instantiating the SPInitLogoutRequestProcessor ", e);
            }
        }
        return null;
    }

    public static String splitAppendedTenantDomain(String issuer) {

        if (StringUtils.isNotBlank(issuer) && issuer.contains(UserCoreConstants.TENANT_DOMAIN_COMBINER)) {
            issuer = issuer.substring(0, issuer.lastIndexOf(UserCoreConstants.TENANT_DOMAIN_COMBINER));
        }

        return issuer;
    }

    /**
     * Check certificate expired or not
     * @param certificate java.security.cert.X509Certificate
     * @return true or false
     */
    public static boolean isCertificateExpired(java.security.cert.X509Certificate certificate) {

        if (certificate != null) {
            Date expiresOn = certificate.getNotAfter();
            Date now = new Date();
            long validityPeriod = (expiresOn.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
            if (validityPeriod >= 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Create single logout request according to the given parameters.
     * @param serviceProviderDO Service provider DO.
     * @param subject Subject identifier.
     * @param sessionIndex Session index.
     * @param rpSessionId Relying party session index.
     * @return SingleLogoutRequestDTO.
     * @throws IdentityException If creation fails.
     */
    public static SingleLogoutRequestDTO createLogoutRequestDTO(SAMLSSOServiceProviderDO serviceProviderDO,
                                                                String subject, String sessionIndex, String rpSessionId,
                                                                String certificateAlias, String tenantDomain)
            throws IdentityException {

        SingleLogoutRequestDTO logoutReqDTO = new SingleLogoutRequestDTO();
        SingleLogoutMessageBuilder logoutMsgBuilder = new SingleLogoutMessageBuilder();

        if (StringUtils.isNotBlank(serviceProviderDO.getSloRequestURL())) {
            logoutReqDTO.setAssertionConsumerURL(serviceProviderDO.getSloRequestURL());
        } else if (StringUtils.isNotBlank(serviceProviderDO.getSloResponseURL())) {
            logoutReqDTO.setAssertionConsumerURL(serviceProviderDO.getSloResponseURL());
        } else {
            logoutReqDTO.setAssertionConsumerURL(serviceProviderDO.getAssertionConsumerUrl());
        }

        LogoutRequest logoutReq = logoutMsgBuilder.buildLogoutRequest(subject, sessionIndex,
                SAMLSSOConstants.SingleLogoutCodes.LOGOUT_USER, logoutReqDTO.getAssertionConsumerURL(),
                serviceProviderDO.getNameIDFormat(), serviceProviderDO.getTenantDomain(),
                serviceProviderDO.getSigningAlgorithmUri(), serviceProviderDO.getDigestAlgorithmUri());

        String logoutReqString = SAMLSSOUtil.marshall(logoutReq);
        logoutReqDTO.setLogoutResponse(logoutReqString);
        logoutReqDTO.setRpSessionId(rpSessionId);
        logoutReqDTO.setCertificateAlias(certificateAlias);
        logoutReqDTO.setTenantDomain(tenantDomain);

        return logoutReqDTO;
    }

    /**
     * Build response status.
     *
     * @param statusCode Status code
     * @param statusMsg Status message
     * @return Response status
     */
    public static Status buildResponseStatus(String statusCode, String statusMsg) {
        Status stat = new StatusBuilder().buildObject();

        // Set the status code
        StatusCode statCode = new StatusCodeBuilder().buildObject();
        statCode.setValue(statusCode);
        stat.setStatusCode(statCode);

        // Set the status Message
        if (statusMsg != null) {
            StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
            statMesssage.setMessage(statusMsg);
            stat.setStatusMessage(statMesssage);
        }
        return stat;
    }

    /**
     * Get service provider config.
     *
     * @param tenantDomain
     * @param issuerName
     * @return
     * @throws IdentityException
     */
    public static SAMLSSOServiceProviderDO getSPConfig(String tenantDomain, String issuerName) throws
            IdentityException {

        SSOServiceProviderConfigManager stratosIdpConfigManager = SSOServiceProviderConfigManager.getInstance();
        SAMLSSOServiceProviderDO serviceProvider = stratosIdpConfigManager.getServiceProvider(issuerName);
        if (serviceProvider != null) {
            return serviceProvider;
        }

        return getSAMLServiceProviderFromRegistry(issuerName, tenantDomain);
    }

    /**
     * Build SAML logout request.
     *
     * @param serviceProviderDO SP for which the logout request is built.
     * @param subject           Subject identifier.
     * @param sessionId         Session index.
     * @return Logout Request.
     * @throws IdentityException If tenant domain is invalid.
     */
    public static LogoutRequest buildLogoutRequest(SAMLSSOServiceProviderDO serviceProviderDO, String subject,
                                                   String sessionId) throws IdentityException {

        String destination;
        if (StringUtils.isNotBlank(serviceProviderDO.getSloRequestURL())) {
            destination = serviceProviderDO.getSloRequestURL();
            if (log.isDebugEnabled()) {
                log.debug("Destination of the logout request is set to the SLO request URL: " +
                        serviceProviderDO.getSloRequestURL() + " of the SP: " + serviceProviderDO.getIssuer());
            }
        } else {
            destination = serviceProviderDO.getAssertionConsumerUrl();
            if (log.isDebugEnabled()) {
                log.debug("Destination of the logout request is set to the ACS URL: " +
                        serviceProviderDO.getAssertionConsumerUrl() + " of the SP: " + serviceProviderDO.getIssuer());
            }
        }

        SingleLogoutMessageBuilder logoutMsgBuilder = new SingleLogoutMessageBuilder();
        LogoutRequest logoutReq = logoutMsgBuilder.buildLogoutRequest(destination, serviceProviderDO.getTenantDomain(),
                sessionId, subject, serviceProviderDO.getNameIDFormat(),
                SAMLSSOConstants.SingleLogoutCodes.LOGOUT_USER);

        return logoutReq;
    }

    /**
     * Get remaining session participants for SLO except for the original issuer.
     *
     * @param sessionIndex Session index.
     * @param issuer       Original issuer.
     * @param isIdPInitSLO Whether IdP initiated SLO or not.
     * @return SP List with remaining session participants for SLO except for the original issuer.
     *
     * @deprecated This method was deprecated to move saml caches to the tenant space.
     * Use {@link #getRemainingSessionParticipantsForSLO(String, String, boolean, String)}  instead.
     */
    @Deprecated
    public static List<SAMLSSOServiceProviderDO> getRemainingSessionParticipantsForSLO(
            String sessionIndex, String issuer, boolean isIdPInitSLO) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return getRemainingSessionParticipantsForSLO(sessionIndex, issuer, isIdPInitSLO,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Get remaining session participants for SLO except for the original issuer.
     *
     * @param sessionIndex          Session index.
     * @param issuer                Original issuer.
     * @param isIdPInitSLO          Whether IdP initiated SLO or not.
     * @param loginTenantDomain     Login Tenant Domain
     * @return SP List with remaining session participants for SLO except for the original issuer.
     *
     */
    public static List<SAMLSSOServiceProviderDO> getRemainingSessionParticipantsForSLO(
            String sessionIndex, String issuer, boolean isIdPInitSLO, String loginTenantDomain) {

        if (isIdPInitSLO) {
            issuer = null;
        }

        SSOSessionPersistenceManager ssoSessionPersistenceManager = SSOSessionPersistenceManager
                .getPersistenceManager();
        SessionInfoData sessionInfoData = ssoSessionPersistenceManager.getSessionInfo(sessionIndex, loginTenantDomain);

        List<SAMLSSOServiceProviderDO> samlssoServiceProviderDOList;

        if (sessionInfoData == null) {
            return new ArrayList<>();
        }

        Map<String, SAMLSSOServiceProviderDO> sessionsList = sessionInfoData.getServiceProviderList();
        samlssoServiceProviderDOList = new ArrayList<>();

        for (Map.Entry<String, SAMLSSOServiceProviderDO> entry : sessionsList.entrySet()) {
            SAMLSSOServiceProviderDO serviceProviderDO = entry.getValue();

            // Logout request should not be created for the issuer.
            if (entry.getKey().equals(issuer)) {
                continue;
            }

            if (serviceProviderDO.isDoSingleLogout()) {
                samlssoServiceProviderDOList.add(serviceProviderDO);
            }
        }

        return samlssoServiceProviderDOList;
    }

    /**
     * Get SessionInfoData.
     *
     * @param sessionIndex Session index.
     * @return Session Info Data.
     *
     * @deprecated This method was deprecated to move SAMLSSOParticipantCache to the tenant space.
     * Use {@link #getSessionInfoData(String, String)}  instead.
     */
    @Deprecated
    public static SessionInfoData getSessionInfoData(String sessionIndex) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return getSessionInfoData(sessionIndex, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Get SessionInfoData.
     *
     * @param sessionIndex       Session index.
     * @param loginTenantDomain  Login Tenant Domain.
     * @return Session Info Data.
     */
    public static SessionInfoData getSessionInfoData(String sessionIndex, String loginTenantDomain) {

        SSOSessionPersistenceManager ssoSessionPersistenceManager = SSOSessionPersistenceManager
                .getPersistenceManager();
        SessionInfoData sessionInfoData = ssoSessionPersistenceManager.getSessionInfo(sessionIndex, loginTenantDomain);

        return sessionInfoData;
    }

    /**
     * Get Session Index.
     *
     * @param sessionId Session id.
     * @return Session Index.
     *
     * @deprecated This method was deprecated to move SAMLSSOSessionIndexCache to the tenant space.
     * Use {@link #getSessionIndex(String, String)}  instead.
     */
    @Deprecated
    public static String getSessionIndex(String sessionId) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return getSessionIndex(sessionId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Get Session Index.
     *
     * @param sessionId         Session id.
     * @param loginTenantDomain Login Tenant Domain.
     * @return Session Index.
     */
    public static String getSessionIndex(String sessionId, String loginTenantDomain) {

        SSOSessionPersistenceManager ssoSessionPersistenceManager = SSOSessionPersistenceManager
                .getPersistenceManager();
        String sessionIndex = ssoSessionPersistenceManager.getSessionIndexFromTokenId(sessionId, loginTenantDomain);

        return sessionIndex;
    }

    /**
     * Construct signature for http redirect.
     *
     * @param httpQueryString       http query string
     * @param signatureAlgorithmURI signature algorithm URI
     * @param credential            X509Credential
     */
    public static void addSignatureToHTTPQueryString(StringBuilder httpQueryString,
                                                     String signatureAlgorithmURI, X509Credential credential) {

        try {
            byte[] rawSignature = XMLSigningUtil.signWithURI(credential, signatureAlgorithmURI,
                   httpQueryString.toString().getBytes(StandardCharsets.UTF_8));

            String base64Signature = Base64Support.encode(rawSignature, Base64Support.UNCHUNKED);

            if (log.isDebugEnabled()) {
                log.debug("Generated digital signature value (base64-encoded) {} " + base64Signature);
            }

            httpQueryString.append("&" + SAMLSSOConstants.SIGNATURE + "=" +
                    URLEncoder.encode(base64Signature, StandardCharsets.UTF_8.name()).trim());

        } catch (org.opensaml.security.SecurityException e) {
            log.error("Unable to sign query string", e);
        } catch (UnsupportedEncodingException e) {
            // UTF-8 encoding is required to be supported by all JVMs.
            log.error("Error while adding signature to HTTP query string", e);
        }
    }

    /**
     * Validate whether the LogoutResponse is a success.
     *
     * @param logoutResponse   Logout Response object.
     * @param certificateAlias Certificate Alias.
     * @param tenantDomain     Tenant domain.
     * @return True if Logout response state success.
     * @throws IdentityException If validating XML signature fails.
     */
    public static boolean validateLogoutResponse(LogoutResponse logoutResponse, String certificateAlias,
                                                 String tenantDomain)
            throws IdentityException {

        if (logoutResponse.getIssuer() == null || logoutResponse.getStatus() == null || logoutResponse
                .getStatus().getStatusCode() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Logout response validation failed due to one of given values are null. " +
                        "Issuer: " + logoutResponse.getIssuer() +
                        " Status: " + logoutResponse.getStatus() +
                        " Status code: " + (logoutResponse.getStatus() != null ? logoutResponse.getStatus()
                        .getStatusCode() : null));
            }
            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Logout response received for issuer: " + logoutResponse.getIssuer()
                    .getValue() + " for tenant domain: " + tenantDomain);
        }

        boolean isSignatureValid = true;

        // Certificate alias will be null if signature validation is disabled in the service provider side.
        if (certificateAlias != null && logoutResponse.isSigned()) {
            isSignatureValid = SAMLSSOUtil.validateXMLSignature(logoutResponse, certificateAlias, tenantDomain);
            if (log.isDebugEnabled()) {
                log.debug("Signature validation result for logout response for issuer: " +
                        logoutResponse.getIssuer().getValue() + " in tenant domain: " + tenantDomain + " is: " +
                        isSignatureValid);
            }
        }
        if (SAMLSSOConstants.StatusCodes.SUCCESS_CODE.equals(logoutResponse.getStatus().getStatusCode()
                .getValue()) && isSignatureValid) {
            return true;
        }

        return false;
    }

    /**
     * Decoding the logout request extracted from the query string.
     *
     * @param logoutRequest Logout request string.
     * @param isPost        Whether the request is post.
     * @return Logout request XML object.
     * @throws IdentityException Error in decoding.
     */
    public static XMLObject decodeSamlLogoutRequest(String logoutRequest, boolean isPost) throws IdentityException {

        XMLObject samlRequest;
        if (isPost) {
            samlRequest = SAMLSSOUtil.unmarshall(SAMLSSOUtil.decodeForPost(logoutRequest));
        } else {
            samlRequest = SAMLSSOUtil.unmarshall(SAMLSSOUtil.decode(logoutRequest));
        }

        return samlRequest;
    }

    public static int getSAMLSessionNotOnOrAfterPeriod(String sessionNotOnOrAfterValue) {

        return Integer.parseInt(sessionNotOnOrAfterValue.trim()) * 60;
    }

    public static boolean isSAMLNotOnOrAfterPeriodDefined(String sessionNotOnOrAfterValue) {

        if (StringUtils.isNotBlank(sessionNotOnOrAfterValue) && StringUtils.isNumeric(sessionNotOnOrAfterValue)) {
            if (Integer.parseInt(sessionNotOnOrAfterValue) > 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Retrieve service provider configs using issuer and tenant domain.
     * @param issuer
     * @param tenantDomain
     * @return
     * @throws IdentityException
     */
    public static SAMLSSOServiceProviderDO getServiceProviderConfig(String issuer, String tenantDomain)
            throws IdentityException {

        String issuerQualifier = SAMLSSOUtil.getIssuerQualifier();
        String issuerWithQualifier = SAMLSSOUtil.getIssuerWithQualifierInThreadLocal();
        if (StringUtils.isBlank(issuerWithQualifier) && StringUtils.isNotBlank(issuerQualifier)) {
            issuerWithQualifier = SAMLSSOUtil.getIssuerWithQualifier(issuer, issuerQualifier);
            if (SAMLSSOUtil.isValidSAMLIssuer(issuer, issuerWithQualifier,
                                SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
                if (log.isDebugEnabled()) {
                    String message = "A SAML request with issuer: " + issuer + " is received." +
                            " A valid Service Provider configuration with the Issuer: " + issuer +
                            " and Issuer Qualifier: " + issuerQualifier + " is identified by the name: " +
                            issuerWithQualifier;
                    log.debug(message);
                }
            }
        }

        if (issuerWithQualifier != null){
            issuer = issuerWithQualifier;
        }

        SAMLSSOUtil.setIssuerWithQualifierInThreadLocal(issuer);

        // Check for SaaS service providers available.
        SSOServiceProviderConfigManager saasServiceProviderConfigManager = SSOServiceProviderConfigManager
                .getInstance();
        SAMLSSOServiceProviderDO serviceProviderConfigs = saasServiceProviderConfigManager.getServiceProvider
                (issuer);
        if (serviceProviderConfigs == null) { // Check for service providers registered in tenant

            if (log.isDebugEnabled()) {
                log.debug("No SaaS SAML service providers found for the issuer : " + issuer + ". Checking for " +
                        "SAML service providers registered in tenant domain : " + tenantDomain);
            }

            serviceProviderConfigs = getSAMLServiceProviderFromRegistry(issuer, tenantDomain);
        }

        return serviceProviderConfigs;
    }

    /**
     * Get issuer qualifier.
     *
     * @return
     */
    public static String getIssuerQualifier() {

        return SAMLSSOUtil.issuerQualifier;
    }

    /**
     * Set the issuer qualifier
     *
     * @param issuerQualifier
     */
    public static void setIssuerQualifier(String issuerQualifier) {

        SAMLSSOUtil.issuerQualifier = issuerQualifier;

    }

    /**
     * Get the issuer value by removing the qualifier.
     *
     * @param issuerWithQualifier issuer value saved in the registry.
     * @return issuer value given as 'issuer' when configuring SAML SP.
     */
    public static String getIssuerWithoutQualifier(String issuerWithQualifier) {

        return StringUtils.substringBeforeLast(issuerWithQualifier, IdentityRegistryResources.QUALIFIER_ID);
    }

    /**
     * Get the issuer value to be added to registry by appending the qualifier.
     *
     * @param issuer value given as 'issuer' when configuring SAML SP.
     * @return issuer value with qualifier appended.
     */
    public static String getIssuerWithQualifier(String issuer, String qualifier) {

        if (StringUtils.isNotBlank(qualifier)) {
            return issuer + IdentityRegistryResources.QUALIFIER_ID + qualifier;
        } else {
            return issuer;
        }
    }

    /**
     * Validate Signature
     * @param authnRequest un-marshal SAML Authentication request
     * @param queryString  marshal saml request
     * @param issuer issuer
     * @return
     */
    public static boolean isSignatureValid(AuthnRequest authnRequest, String queryString, String issuer,
                                           java.security.cert.X509Certificate certificate) {

        try {
            if (queryString != null && queryString.contains(SAML_REQUEST)) {
                // DEFLATE signature in Redirect Binding.
                return validateDeflateSignature(queryString, issuer, certificate);
            } else {
                // XML signature in SAML Request message for POST Binding.
                return validateXMLSignature(authnRequest, certificate);
            }
        } catch (IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Signature Validation failed for the SAMLRequest : Failed to validate the SAML Assertion " +
                        "of the Issuer " + authnRequest.getProviderName(), e);
            }
            return false;
        }
    }

    /**
     * Appends service provider qualifier to the issuer if a service provider qualifier is present in the request.
     *
     * @param queryParamDTOs query parameters present in the request.
     * @param issuer service provider entity id present in the request.
     * @return issuer value with qualifier appended.
     */
    public static String resolveIssuerQualifier(QueryParamDTO[] queryParamDTOs, String issuer) {

        String issuerQualifier = getSPQualifier(queryParamDTOs);
        if (StringUtils.isNotBlank(issuerQualifier)) {
            return SAMLSSOUtil.getIssuerWithQualifier(issuer, issuerQualifier);
        } else {
            return issuer;
        }
    }

    /**
     * Get the user id from the authenticated user.
     *
     * @param authenticatedUser AuthenticationContext.
     * @return User id.
     */
    public static Optional<String> getUserId(AuthenticatedUser authenticatedUser) {

        if (authenticatedUser == null) {
            return Optional.empty();
        }
        try {
            if (authenticatedUser.getUserId() != null) {
                return Optional.ofNullable(authenticatedUser.getUserId());
            }
        } catch (UserIdNotFoundException e) {
            log.debug("Error while getting the user id from the authenticated user.", e);
        }
        return Optional.empty();
    }
    
    /**
     * Build the JSON object of the SAMLSSOServiceProviderDO and return it as a Map.
     *
     * @param app SAMLSSOServiceProviderDO object.
     * @return Map of <String, Object> of the SAMLSSOServiceProviderDO.
     */
    public static Map<String, Object> buildSPData(SAMLSSOServiceProviderDO app) {
        
        if (app == null) {
            return new HashMap<>();
        }
        
        Gson gson = new Gson();
        String json = gson.toJson(app);
        return gson.fromJson(json, new TypeToken<Map<String, Object>>() {
        }.getType());
    }

    public static String  buildSPDataJSONString(SAMLSSOServiceProviderDO app) {

        Gson gson = new Gson();
        return gson.toJson(app);
    }

    public static Map<String, Object> buildSPDataFromJsonString(String appJsonString) {

        Gson gson = new Gson();
        return gson.fromJson(appJsonString, new TypeToken<Map<String, Object>>() {
        }.getType());
    }

    private static String getSPQualifier(QueryParamDTO[] queryParamDTOs) {

        for (QueryParamDTO queryParamDTO : queryParamDTOs) {
            if (SAMLSSOConstants.QueryParameter.SP_QUALIFIER.toString().equals(queryParamDTO.getKey())) {
                return queryParamDTO.getValue();
            }
        }
        return null;
    }

    /**
     * Resolves the public service url given the default context and the url picked from the configuration based on
     * the 'tenant_context.enable_tenant_qualified_urls' mode set in deployment.toml.
     *
     * @param defaultUrlContext default url context path
     * @param urlFromConfig     url picked from the file configuration
     * @return absolute public url of the service if 'enable_tenant_qualified_urls' is 'true', else returns the url
     * from the file config
     * @throws URLBuilderException when fail to build the absolute public url
     */
    private static String resolveUrl(String defaultUrlContext, String urlFromConfig) throws URLBuilderException {

        if (!IdentityTenantUtil.isTenantQualifiedUrlsEnabled() && StringUtils.isNotBlank(urlFromConfig)) {
            if (log.isDebugEnabled()) {
                log.debug("Resolved URL:" + urlFromConfig + " from file configuration for default url context: " +
                        defaultUrlContext);
            }
            return urlFromConfig;
        }

        return ServiceURLBuilder.create().addPath(defaultUrlContext).build().getAbsolutePublicURL();
    }

    private static int getTenantIdFromDomain(String tenantDomain) throws IdentitySAML2SSOException {

        int tenantId;
        try {
            tenantId = SAMLSSOUtil.getRealmService().getTenantManager().getTenantId(tenantDomain);
            if (tenantId == MultitenantConstants.INVALID_TENANT_ID) {
                throw new IdentitySAML2ClientException("Invalid tenant domain: " + tenantDomain);
            }
        } catch (UserStoreException e) {
            throw new IdentitySAML2SSOException("Error occurred while retrieving tenant id for " +
                    "tenant domain : " + tenantDomain, e);
        }

        return tenantId;
    }

    private static SAMLSSOServiceProviderDO getSAMLServiceProviderFromRegistry(String issuer, String tenantDomain)
            throws IdentitySAML2SSOException {

        if (StringUtils.isBlank(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        int tenantId = getTenantIdFromDomain(tenantDomain);
        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext privilegedCarbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
            privilegedCarbonContext.setTenantId(tenantId);
            privilegedCarbonContext.setTenantDomain(tenantDomain);

            IdentityTenantUtil.getTenantRegistryLoader().loadTenantRegistry(tenantId);
            return IdentitySAMLSSOServiceComponentHolder.getInstance().getSAMLSSOServiceProviderManager()
                    .getServiceProvider(issuer, tenantId);

        } catch (IdentityException | RegistryException e) {
            throw new IdentitySAML2SSOException("Error occurred while retrieving SAML service provider for "
                    + "issuer : " + issuer + " in tenant domain : " + tenantDomain);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    /**
     * Check whether SAML logout response signing is enabled for IDP initiated SSO.
     * @return true if enabled.
     */
    public static boolean isSAMLIdpInitLogoutResponseSigningEnabled() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(
                SAMLSSOConstants.SAML_IDP_INIT_LOGOUT_RESPONSE_SIGNING_ENABLED));
    }

    /**
     * SeparateMultiAttributesFromIdP config is used to separate the multi-valued attributes sent from the IdPs.
     * This config is used when the SP doesn't request any claim in IS, and all the claims from the IdP are passed
     * to the SP.
     *
     * @return false if 'separateMultiAttributesFromIdP' config is disabled. By default, this config is enabled in the
     * product.
     */
    public static boolean separateMultiAttributesFromIdPEnabled() {

        String separateMultiAttributesFromIdPEnabledConfig = IdentityUtil.getProperty(
                SAMLSSOConstants.SEPARATE_MULTI_ATTRS_FROM_IDPS_USING_ATTRIBUTE_SEPARATOR);
        if (StringUtils.isNotEmpty(separateMultiAttributesFromIdPEnabledConfig)) {
            return Boolean.parseBoolean(separateMultiAttributesFromIdPEnabledConfig);
        } else {
            return true;
        }
    }

    /**
     * Validate that the given attribute name format is a valid value.
     *
     * @param attributeNameFormat - Attribute name format value that requires validation.
     * @return A boolean result indicating whether the provided name format is valid.
     */
    public static boolean validateAttributeNameFormat(String attributeNameFormat) {

        for (NameFormat nameFormat : NameFormat.values()) {
            if (StringUtils.equals(nameFormat.toString(), attributeNameFormat)) {
                return true;
            }
        }

        return false;
    }
}
