/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.samlnew.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xerces.impl.Constants;
import org.apache.xerces.util.SecurityManager;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.util.Base64;
import org.osgi.framework.BundleContext;
import org.osgi.service.http.HttpService;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.SAML2SSOFederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.persistence.IdentityPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.samlnew.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.samlnew.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.samlnew.bean.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.samlnew.bean.message.request.SAMLIdentityRequest;
import org.wso2.carbon.identity.sso.samlnew.builders.X509CredentialImpl;
import org.wso2.carbon.identity.sso.samlnew.builders.assertion.DefaultSAMLAssertionBuilder;
import org.wso2.carbon.identity.sso.samlnew.builders.assertion.SAMLAssertionBuilder;
import org.wso2.carbon.identity.sso.samlnew.builders.encryption.SSOEncrypter;
import org.wso2.carbon.identity.sso.samlnew.builders.signature.SSOSigner;
import org.wso2.carbon.identity.sso.samlnew.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.samlnew.validators.SAML2HTTPRedirectSignatureValidator;
import org.wso2.carbon.identity.sso.samlnew.validators.SPInitSSOAuthnRequestValidator;
import org.wso2.carbon.identity.sso.samlnew.validators.SSOAuthnRequestValidator;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class SAMLSSOUtil {

    private static final ThreadLocal<Boolean> isSaaSApplication = new ThreadLocal<>();
    private static final ThreadLocal<String> userTenantDomainThreadLocal = new ThreadLocal<>();
    private static int singleLogoutRetryCount = 5;
    private static long singleLogoutRetryInterval = 60000;

    private static RealmService realmService;
    private static ThreadLocal tenantDomainInThreadLocal = new ThreadLocal();
    private static SAMLAssertionBuilder samlAssertionBuilder = null;
    private static SAML2HTTPRedirectSignatureValidator samlHTTPRedirectSignatureValidator = null;
    private static String sPInitSSOAuthnRequestValidatorClassName = null;
    private static SSOSigner ssoSigner = null;
    private static SSOEncrypter ssoEncrypter = null;
    private static BundleContext bundleContext;
    private static RegistryService registryService;
    private static ConfigurationContextService configCtxService;
    private static HttpService httpService;

    private static Log log = LogFactory.getLog(SAMLSSOUtil.class);
    private static final String SECURITY_MANAGER_PROPERTY = Constants.XERCES_PROPERTY_PREFIX +
            Constants.SECURITY_MANAGER_PROPERTY;
    private static final int ENTITY_EXPANSION_LIMIT = 0;
    private static boolean isBootStrapped = false;

    public static boolean isSaaSApplication() {

        if (isSaaSApplication == null) {
            // this is the default behavior.
            return true;
        }

        Boolean value = isSaaSApplication.get();

        if (value != null) {
            return value;
        }

        return false;
    }

    public static void setIsSaaSApplication(boolean isSaaSApp) {
        isSaaSApplication.set(isSaaSApp);
    }

    public static void removeSaaSApplicationThreaLocal() {
        isSaaSApplication.remove();
    }

    public static String getUserTenantDomain() {

        if (userTenantDomainThreadLocal == null) {
            // this is the default behavior.
            return null;
        }

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
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);

            documentBuilderFactory.setExpandEntityReferences(false);
            documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            org.apache.xerces.util.SecurityManager securityManager = new SecurityManager();
            securityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT);
            documentBuilderFactory.setAttribute(SECURITY_MANAGER_PROPERTY, securityManager);

            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            docBuilder.setEntityResolver(new CarbonEntityResolver());
            inputStream = new ByteArrayInputStream(authReqStr.trim().getBytes(StandardCharsets.UTF_8));
            Document document = docBuilder.parse(inputStream);
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
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

            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);

            byteArrayOutputStrm = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(byteArrayOutputStrm);
            writer.write(element, output);
            return byteArrayOutputStrm.toString(StandardCharsets.UTF_8.name());
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
                Base64.encodeBytes(xmlString.getBytes(StandardCharsets.UTF_8),
                        Base64.DONT_BREAK_LINES);
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
            byte[] xmlBytes = encodedStr.getBytes(StandardCharsets.UTF_8.name());
            byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

            try {
                Inflater inflater = new Inflater(true);
                inflater.setInput(base64DecodedByteArray);
                byte[] xmlMessageBytes = new byte[5000];
                int resultLength = inflater.inflate(xmlMessageBytes);

                if (!inflater.finished()) {
                    throw new RuntimeException("End of the compressed data stream has NOT been reached");
                }

                inflater.end();
                String decodedString = new String(xmlMessageBytes, 0, resultLength, StandardCharsets.UTF_8.name());
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
        } catch (IOException e) {
            throw IdentityException.error("Error when decoding the SAML Request.", e);
        }

    }


    public static String decodeForPost(String encodedStr)
            throws IdentityException {
        try {
            org.apache.commons.codec.binary.Base64 base64Decoder = new org.apache.commons.codec.binary.Base64();
            byte[] xmlBytes = encodedStr.getBytes(StandardCharsets.UTF_8.name());
            byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

            String decodedString = new String(base64DecodedByteArray, StandardCharsets.UTF_8.name());
            if (log.isDebugEnabled()) {
                log.debug("Request message " + decodedString);
            }
            return decodedString;

        } catch (IOException e) {
            throw IdentityException.error(
                    "Error when decoding the SAML Request.", e);
        }

    }

    public static void doBootstrap() {
        if (!isBootStrapped) {
            try {
                DefaultBootstrap.bootstrap();
                isBootStrapped = true;
            } catch (ConfigurationException e) {
                log.error("Error in bootstrapping the OpenSAML2 library", e);
            }
        }
    }

    public static String getNotificationEndpoint(){
        String redirectURL = IdentityUtil.getProperty(IdentityConstants.ServerConfig
                .NOTIFICATION_ENDPOINT);
        if (StringUtils.isBlank(redirectURL)){
            redirectURL = IdentityUtil.getServerURL(SAMLSSOConstants.NOTIFICATION_ENDPOINT, false, false);
        }
        return redirectURL;
    }

    /**
     * build the error response
     *
     * @param status
     * @param message
     * @return decoded response
     * @throws org.wso2.carbon.identity.base.IdentityException
     */
    public static String buildErrorResponse(String status, String message, String destination) throws IdentityException, IOException {

        List<String> statusCodeList = new ArrayList<String>();
        statusCodeList.add(status);
        //Do below in the response builder
        Response response = buildResponse(null,statusCodeList,message,destination);
        String errorResp = compressResponse(SAMLSSOUtil.marshall(response));
        return errorResp;
    }

    public static String buildErrorResponse(String id, List<String> statusCodes, String statusMsg, String destination)
            throws IdentityException {
        Response response = buildResponse(id, statusCodes, statusMsg, destination);
        return SAMLSSOUtil.encode(SAMLSSOUtil.marshall(response));
    }

    /**
     * Build the error response
     *
     * @return
     */
    public static Response buildResponse(String inResponseToID,List<String> statusCodes,String statusMsg,String destination) throws IdentityException {

        Response response = new ResponseBuilder().buildObject();

        if (statusCodes == null || statusCodes.isEmpty()) {
            throw IdentityException.error("No Status Values");
        }
        response.setIssuer(SAMLSSOUtil.getIssuer());
            Status status = new StatusBuilder().buildObject();
            StatusCode statusCode = null;
            for (String statCode : statusCodes) {
                statusCode = buildStatusCode(statCode, statusCode);
            }
            status.setStatusCode(statusCode);
            buildStatusMsg(status, statusMsg);
            response.setStatus(status);
            response.setVersion(SAMLVersion.VERSION_20);
            response.setID(SAMLSSOUtil.createID());
            if (inResponseToID != null) {
                response.setInResponseTo(inResponseToID);
            }
            if (destination != null) {
                response.setDestination(destination);
            }
            response.setIssueInstant(new DateTime());
            return response;
    }

    public static String splitAppendedTenantDomain(String issuer) {

        if (issuer.contains(UserCoreConstants.TENANT_DOMAIN_COMBINER)) {
            issuer = issuer.substring(0, issuer.lastIndexOf(UserCoreConstants.TENANT_DOMAIN_COMBINER));
        }
        return issuer;
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
        return Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
    }

    /**
     * Validates the request message's signature. Validates the signature of
     * both HTTP POST Binding and HTTP Redirect Binding.
     *
     * @param messageContext
     * @return
     */
    public static boolean validateAuthnRequestSignature(SAMLMessageContext messageContext) {

        if (log.isDebugEnabled()) {
            log.debug("Validating SAML Request signature");
        }

        SAMLSSOServiceProviderDO serviceProvider = messageContext.getSamlssoServiceProviderDO();

        String domainName = messageContext.getTenantDomain();
        if (messageContext.isStratosDeployment()) {
            domainName = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        String alias = serviceProvider.getCertAlias();
        RequestAbstractType request = null;
        try {
            String decodedReq = null;

            if (messageContext.getRequest().isRedirect()) {
                decodedReq = SAMLSSOUtil.decode(messageContext.getRequestMessageString());
            } else {
                decodedReq = SAMLSSOUtil.decodeForPost(messageContext.getRequestMessageString());
            }
            request = (RequestAbstractType) SAMLSSOUtil.unmarshall(decodedReq);
        } catch (IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Signature Validation failed for the SAMLRequest : Failed to unmarshall the SAML Assertion", e);
            }
        }

        try {
            if (messageContext.getRequest().isRedirect()) {
                // DEFLATE signature in Redirect Binding
                return validateDeflateSignature(messageContext.getRequest(), messageContext.getIssuer(), alias,
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
     * Signature validation for HTTP Redirect Binding
     * @param request
     * @param issuer
     * @param alias
     * @param domainName
     * @return
     * @throws IdentityException
     */
    public static boolean validateDeflateSignature(SAMLIdentityRequest request, String issuer,
                                                   String alias, String domainName) throws IdentityException {
        try {

            synchronized (Runtime.getRuntime().getClass()) {
                samlHTTPRedirectSignatureValidator = (SAML2HTTPRedirectSignatureValidator) Class.forName(IdentityUtil.getProperty(
                        "SSOService.SAML2HTTPRedirectSignatureValidator").trim()).newInstance();
                samlHTTPRedirectSignatureValidator.init();
            }

            return samlHTTPRedirectSignatureValidator.validateSignature(request, issuer,
                    alias, domainName);

        } catch (org.opensaml.xml.security.SecurityException e) {
            log.error("Error validating deflate signature", e);
            return false;
        } catch (IdentitySAML2SSOException e) {
            log.warn("Signature validation failed for the SAML Message : Failed to construct the X509CredentialImpl for the alias " +
                    alias, e);
            return false;
        } catch (ClassNotFoundException e) {
            throw IdentityException.error("Class not found: "
                    + IdentityUtil.getProperty("SSOService.SAML2HTTPRedirectSignatureValidator"), e);
        } catch (InstantiationException e) {
            throw IdentityException.error("Error while instantiating class: "
                    + IdentityUtil.getProperty("SSOService.SAML2HTTPRedirectSignatureValidator"), e);
        } catch (IllegalAccessException e) {
            throw IdentityException.error("Illegal access to class: "
                    + IdentityUtil.getProperty("SSOService.SAML2HTTPRedirectSignatureValidator"), e);
        }
    }

    /**
     * Validate the signature of an assertion
     *
     * @param request    SAML Assertion, this could be either a SAML Request or a
     *                   LogoutRequest
     * @param alias      Certificate alias against which the signature is validated.
     * @param domainName domain name of the subject
     * @return true, if the signature is valid.
     */
    public static boolean validateXMLSignature(RequestAbstractType request, String alias,
                                               String domainName) throws IdentityException {

        boolean isSignatureValid = false;

        if (request.getSignature() != null) {
            try {
                X509Credential cred = SAMLSSOUtil.getX509CredentialImplForTenant(domainName, alias);

                synchronized (Runtime.getRuntime().getClass()) {
                    ssoSigner = (SSOSigner) Class.forName(IdentityUtil.getProperty(
                            "SSOService.SAMLSSOSigner").trim()).newInstance();
                    ssoSigner.init();
                }
                return ssoSigner.validateXMLSignature(request, cred, alias);
            } catch (IdentitySAML2SSOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature validation failed for the SAML Message : Failed to construct the " +
                            "X509CredentialImpl for the alias " + alias, e);
                }
            } catch (IdentityException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Validation Failed for the SAML Assertion : Signature is invalid.", e);
                }
            } catch (ClassNotFoundException e) {
                throw IdentityException.error("Class not found: "
                        + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
            } catch (InstantiationException e) {
                throw IdentityException.error("Error while instantiating class: "
                        + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
            } catch (IllegalAccessException e) {
                throw IdentityException.error("Illegal access to class: "
                        + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while validating XML signature.", e);
                }
            }
        }
        return isSignatureValid;
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
            String configDestination = IdentityUtil.getProperty(IdentityConstants.ServerConfig.SSO_IDP_URL);
            if (StringUtils.isBlank(configDestination)) {
                configDestination = IdentityUtil.getServerURL(SAMLSSOConstants.SAMLSSO_URL, true, true);
            }
            destinationURLs.add(configDestination);
        }

        return destinationURLs;
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

            IdentityPersistenceManager persistenceManager = IdentityPersistenceManager.getPersistanceManager();
            Registry registry = (Registry) PrivilegedCarbonContext.getThreadLocalCarbonContext().getRegistry
                    (RegistryType.SYSTEM_CONFIGURATION);
            SAMLSSOServiceProviderDO spDO = persistenceManager.getServiceProvider(registry, issuerName);
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

    public static boolean isSAMLIssuerExists(String issuerName, String tenantDomain) throws IdentitySAML2SSOException {
///@TODO : DO we need this?
//        SSOServiceProviderConfigManager stratosIdpConfigManager = SSOServiceProviderConfigManager.getInstance();
//        SAMLSSOServiceProviderDO serviceProvider = stratosIdpConfigManager.getServiceProvider(issuerName);
//        if (serviceProvider != null) {
//            return true;
//        }

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
            IdentityPersistenceManager persistenceManager = IdentityPersistenceManager.getPersistanceManager();
            Registry registry = (Registry) PrivilegedCarbonContext.getThreadLocalCarbonContext().getRegistry
                    (RegistryType.SYSTEM_CONFIGURATION);
            return persistenceManager.isServiceProviderExists(registry, issuerName);
        } catch (IdentityException e) {
            throw new IdentitySAML2SSOException("Error occurred while validating existence of SAML service provider " +
                    "'" + issuerName + "' in the tenant domain '" + tenantDomain + "'");
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
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

    public static RealmService getRealmService() {
        return realmService;
    }

    public static void setRealmService(RealmService realmService) {
        SAMLSSOUtil.realmService = realmService;
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

    /**
     * Get the Issuer
     *
     * @return Issuer
     */
    public static Issuer getIssuer() throws IdentityException {

        return getIssuerFromTenantDomain(getTenantDomainFromThreadLocal());
    }

    public static Assertion buildSAMLAssertion(SAMLMessageContext context, DateTime notOnOrAfter,
                                               String sessionId) throws IdentityException {

        doBootstrap();
        String assertionBuilderClass = null;
        try {
            assertionBuilderClass = IdentityUtil.getProperty("SSOService.SAMLSSOAssertionBuilder").trim();
            if (StringUtils.isBlank(assertionBuilderClass)) {
                assertionBuilderClass = DefaultSAMLAssertionBuilder.class.getName();
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("SAMLSSOAssertionBuilder configuration is set to default builder ", e);
            }
            assertionBuilderClass = DefaultSAMLAssertionBuilder.class.getName();
        }

        try {

            synchronized (Runtime.getRuntime().getClass()) {
                samlAssertionBuilder = (SAMLAssertionBuilder) Class.forName(assertionBuilderClass).newInstance();
                samlAssertionBuilder.init();
            }
            return samlAssertionBuilder.buildAssertion(context, notOnOrAfter, sessionId);

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

    public static SSOAuthnRequestValidator getSPInitSSOAuthnRequestValidator(SAMLMessageContext messageContext) {
        if (sPInitSSOAuthnRequestValidatorClassName == null || "".equals(sPInitSSOAuthnRequestValidatorClassName)) {
            try {
                return new SPInitSSOAuthnRequestValidator(messageContext);
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
                return (SSOAuthnRequestValidator) clazz.getDeclaredConstructor(SAMLMessageContext.class).newInstance
                        (messageContext);

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

    public static Issuer getIssuerFromTenantDomain(String tenantDomain) throws IdentityException {

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

            if (MultitenantConstants.INVALID_TENANT_ID == tenantId) {
                throw IdentityException.error("Invalid tenant domain - '" + tenantDomain + "'");
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
                SAML2SSOFederatedAuthenticatorConfig samlFedAuthnConfig = new SAML2SSOFederatedAuthenticatorConfig
                        (config);
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

    public static String createID() {

        try {
            SecureRandomIdentifierGenerator generator = new SecureRandomIdentifierGenerator();
            return generator.generateIdentifier();
        } catch (NoSuchAlgorithmException e) {
            log.error("Error while building Secure Random ID", e);
            //TODO : throw exception and break the flow
        }
        return null;

    }

    /**
     * Generate the key store name from the domain name
     *
     * @param tenantDomain tenant domain name
     * @return key store file name
     */
    public static String generateKSNameFromDomainName(String tenantDomain) {

        String ksName = tenantDomain.trim().replace(".", "-");
        return ksName + ".jks";
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
                        "SSOService.SAMLSSOSigner").trim()).newInstance();
                ssoSigner.init();
            }

            return ssoSigner.setSignature(request, signatureAlgorithm, digestAlgorithm, cred);

        } catch (ClassNotFoundException e) {
            throw IdentityException.error("Class not found: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
        } catch (InstantiationException e) {
            throw IdentityException.error("Error while instantiating class: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
        } catch (IllegalAccessException e) {
            throw IdentityException.error("Illegal access to class: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
        } catch (Exception e) {
            throw IdentityException.error("Error while signing the XML object.", e);
        }
    }

    /**
     * Build the StatusCode for Status of Response
     *
     * @param parentStatusCode
     * @param childStatusCode
     * @return
     */
    private static StatusCode buildStatusCode(String parentStatusCode, StatusCode childStatusCode) throws
            IdentityException {
        if (parentStatusCode == null) {
            throw IdentityException.error("Invalid SAML Response Status Code");
        }

        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue(parentStatusCode);

        //Set the status Message
        if (childStatusCode != null) {
            statusCode.setStatusCode(childStatusCode);
            return statusCode;
        } else {
            return statusCode;
        }
    }

    /**
     * Set the StatusMessage for Status of Response
     *
     * @param statusMsg
     * @return
     */
    private static  Status buildStatusMsg(Status status, String statusMsg) {
        if (statusMsg != null) {
            StatusMessage statusMesssage = new StatusMessageBuilder().buildObject();
            statusMesssage.setMessage(statusMsg);
            status.setStatusMessage(statusMesssage);
        }
        return status;
    }

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

    /**
     * Get the X509CredentialImpl object for a particular tenant
     *
     * @param tenantDomain
     * @param alias
     * @return X509CredentialImpl object containing the public certificate of
     * that tenant
     * @throws org.wso2.carbon.identity.sso.samlnew.exception.IdentitySAML2SSOException Error when creating X509CredentialImpl object
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
                keyStore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(tenantDomain));
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
     * Return a Array of Claims containing requested attributes and values
     *
     * @param context
     * @return Map with attributes and values
     * @throws IdentityException
     */
    public static Map<String, String> getAttributes(SAMLMessageContext context
    ) throws IdentityException {

        int index = 0;

        SAMLSSOServiceProviderDO spDO = getServiceProviderConfig(context);

        if (!context.isIdpInitSSO()) {

            if (context.getAttributeConsumingServiceIndex() == 0) {
                //SP has not provide a AttributeConsumingServiceIndex in the authnReqDTO
                if (StringUtils.isNotBlank(spDO.getAttributeConsumingServiceIndex()) && spDO
                        .isEnableAttributesByDefault()) {
                    index = Integer.parseInt(spDO.getAttributeConsumingServiceIndex());
                } else {
                    return null;
                }
            } else {
                //SP has provide a AttributeConsumingServiceIndex in the authnReqDTO
                index = context.getAttributeConsumingServiceIndex();
            }
        } else {
            if (StringUtils.isNotBlank(spDO.getAttributeConsumingServiceIndex()) && spDO.isEnableAttributesByDefault
                    ()) {
                index = Integer.parseInt(spDO.getAttributeConsumingServiceIndex());
            } else {
                return null;
            }

        }


		/*
         * IMPORTANT : checking if the consumer index in the request matches the
		 * given id to the SP
		 */
        if (spDO.getAttributeConsumingServiceIndex() == null ||
                "".equals(spDO.getAttributeConsumingServiceIndex()) ||
                index != Integer.parseInt(spDO.getAttributeConsumingServiceIndex())) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid AttributeConsumingServiceIndex in AuthnRequest");
            }
            return Collections.emptyMap();
        }

        Map<String, String> claimsMap = new HashMap<String, String>();
        if (context.getAuthenticationResult().getSubject().getUserAttributes() != null) {
            for (Map.Entry<ClaimMapping, String> entry : context.getAuthenticationResult().getSubject()
                    .getUserAttributes().entrySet()) {
                claimsMap.put(entry.getKey().getRemoteClaim().getClaimUri(), entry.getValue());
            }
        }
        return claimsMap;
    }

    /**
     * Returns the configured service provider configurations. The
     * configurations are taken from the user registry or from the
     * sso-idp-config.xml configuration file. In Stratos deployment the
     * configurations are read from the sso-idp-config.xml file.
     *
     * @param context
     * @return
     * @throws IdentityException
     */
    public static SAMLSSOServiceProviderDO getServiceProviderConfig(SAMLMessageContext context)
            throws IdentityException {
        try {
            SSOServiceProviderConfigManager stratosIdpConfigManager = SSOServiceProviderConfigManager
                    .getInstance();
            SAMLSSOServiceProviderDO ssoIdpConfigs = stratosIdpConfigManager
                    .getServiceProvider(context.getIssuer());
            if (ssoIdpConfigs == null) {
                IdentityTenantUtil.initializeRegistry(PrivilegedCarbonContext.getThreadLocalCarbonContext()
                        .getTenantId(), PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain());
                IdentityPersistenceManager persistenceManager = IdentityPersistenceManager.getPersistanceManager();
                Registry registry = (Registry) PrivilegedCarbonContext.getThreadLocalCarbonContext().getRegistry
                        (RegistryType.SYSTEM_CONFIGURATION);
                ssoIdpConfigs = persistenceManager.getServiceProvider(registry, context.getIssuer());
                context.setStratosDeployment(false); // not stratos
            } else {
                context.setStratosDeployment(true); // stratos deployment
            }
            return ssoIdpConfigs;
        } catch (Exception e) {
            throw IdentityException.error("Error while reading Service Provider configurations", e);
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

    public static int getSAMLResponseValidityPeriod() {
        if (StringUtils.isNotBlank(IdentityUtil.getProperty(IdentityConstants.ServerConfig
                .SAML_RESPONSE_VALIDITY_PERIOD))) {
            return Integer.parseInt(IdentityUtil.getProperty(
                    IdentityConstants.ServerConfig.SAML_RESPONSE_VALIDITY_PERIOD).trim());
        } else {
            return 5;
        }
    }
}
