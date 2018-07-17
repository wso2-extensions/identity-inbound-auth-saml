/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.sso.saml.admin;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

/**
 * This class reads the Service Providers info from sso-idp-config.xml and add them to the
 * in-memory service provider map exposed by org.wso2.carbon.identity.sso.saml.
 * SSOServiceProviderConfigManager class.
 */
public class FileBasedConfigManager {

    private static Log log = LogFactory.getLog(FileBasedConfigManager.class);

    private static volatile FileBasedConfigManager instance = null;

    private FileBasedConfigManager() {

    }

    public static FileBasedConfigManager getInstance() {
        if (instance == null) {
            synchronized (FileBasedConfigManager.class) {
                if (instance == null) {
                    instance = new FileBasedConfigManager();
                }
            }
        }
        return instance;
    }

    /**
     * Read the service providers from file, create SAMLSSOServiceProviderDO beans and add them
     * to the service providers map.
     */
    public void addServiceProviders() {
        SAMLSSOServiceProviderDO[] serviceProviders = readServiceProvidersFromFile();
        if (serviceProviders != null) {
            SSOServiceProviderConfigManager configManager = SSOServiceProviderConfigManager.getInstance();
            for (SAMLSSOServiceProviderDO spDO : serviceProviders) {
                if (spDO != null) {
                    configManager.addServiceProvider(spDO.getIssuer(), spDO);
                    log.info("A SSO Service Provider is registered for : " + spDO.getIssuer());
                }
            }
        }
    }

    /**
     * Read the SP info from the sso-idp-config.xml and create an array of SAMLSSOServiceProviderDO
     * beans
     *
     * @return An array of SAMLSSOServiceProviderDO beans
     */
    private SAMLSSOServiceProviderDO[] readServiceProvidersFromFile() {
        Document document = null;
        try {
            String configFilePath = IdentityUtil.getIdentityConfigDirPath() + File.separator + "sso-idp-config.xml";

            if (!isFileExisting(configFilePath)) {
                log.warn("sso-idp-config.xml does not exist in the "+IdentityUtil.getIdentityConfigDirPath() +
                        " directory. The system may depend on the service providers added through the UI.");
                return new SAMLSSOServiceProviderDO[0];
            }

            Path filePath = Paths.get(configFilePath);
            InputStream stream = Files.newInputStream(filePath);

            DocumentBuilderFactory factory = IdentityUtil.getSecuredDocumentBuilderFactory();
            DocumentBuilder builder = factory.newDocumentBuilder();
            document = builder.parse(stream);
        } catch (Exception e) {
            log.error("Error reading Service Providers from sso-idp-config.xml", e);
            return new SAMLSSOServiceProviderDO[0];
        }

        Element element = document.getDocumentElement();
        NodeList nodeSet = element.getElementsByTagName(SAMLSSOConstants.FileBasedSPConfig.SERVICE_PROVIDER);
        SAMLSSOServiceProviderDO[] serviceProviders = new SAMLSSOServiceProviderDO[nodeSet.getLength()];
        boolean singleLogout = true;
        boolean signAssertion = true;
        boolean validateSignature = false;
        boolean encryptAssertion = false;
        String certAlias = null;

        for (int i = 0; i < nodeSet.getLength(); i++) {
            Element elem = (Element) nodeSet.item(i);
            SAMLSSOServiceProviderDO spDO = new SAMLSSOServiceProviderDO();
            spDO.setIssuer(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.ISSUER));

            List<String> assertionConsumerUrls = new ArrayList<>();
            for(String assertionConsumerUrl : getTextValueList(elem, SAMLSSOConstants
                    .FileBasedSPConfig.ASSERTION_CONSUMER_URL)) {
                assertionConsumerUrls.add(IdentityUtil.fillURLPlaceholders(assertionConsumerUrl.trim()));
            }
            spDO.setAssertionConsumerUrls(assertionConsumerUrls);

            spDO.setDefaultAssertionConsumerUrl(IdentityUtil
                    .fillURLPlaceholders(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.DEFAULT_ACS_URL)));
            spDO.setLoginPageURL(IdentityUtil
                    .fillURLPlaceholders(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.CUSTOM_LOGIN_PAGE)));

            if ((getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.NAME_ID_FORMAT)) != null) {
                spDO.setNameIDFormat(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.NAME_ID_FORMAT));
            }

            if ((getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.SINGLE_LOGOUT)) != null) {
                singleLogout = Boolean.valueOf(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.SINGLE_LOGOUT));
                spDO.setSloResponseURL(IdentityUtil
                        .fillURLPlaceholders(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.SLO_RESPONSE_URL)));
                spDO.setSloRequestURL(IdentityUtil
                        .fillURLPlaceholders(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.SLO_REQUEST_URL)));
            }

            if ((getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.SIGN_ASSERTION)) != null) {
                signAssertion = Boolean.valueOf(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.SIGN_ASSERTION));
            }
            if ((getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.SIG_VALIDATION)) != null) {
                validateSignature = Boolean.valueOf(getTextValue(elem, SAMLSSOConstants
                        .FileBasedSPConfig.SIG_VALIDATION));
            }
            if ((getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.ENCRYPT_ASSERTION)) != null) {
                encryptAssertion = Boolean.valueOf(getTextValue(elem, SAMLSSOConstants
                        .FileBasedSPConfig.ENCRYPT_ASSERTION));
            }
            if (getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.SSO_DEFAULT_SIGNING_ALGORITHM) != null) {
                spDO.setSigningAlgorithmUri(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig
                        .SSO_DEFAULT_SIGNING_ALGORITHM));
            } else {
                spDO.setSigningAlgorithmUri(IdentityApplicationManagementUtil.getSigningAlgoURIByConfig());
            }
            if (getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.SSO_DEFAULT_DIGEST_ALGORITHM) != null) {
                spDO.setDigestAlgorithmUri(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig
                        .SSO_DEFAULT_DIGEST_ALGORITHM));
            } else {
                spDO.setDigestAlgorithmUri(IdentityApplicationManagementUtil.getDigestAlgoURIByConfig());
            }
            if (validateSignature || encryptAssertion) {

                boolean couldFillCertificateDetails = fillCertificateDetails(spDO, elem);

                // If the certificate details couldn't be filled don't add this SP. Continue with the next one.
                if (!couldFillCertificateDetails) {
                    continue;
                }
            }
            if (Boolean.valueOf(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.ATTRIBUTE_PROFILE))) {
                spDO.setEnableAttributesByDefault(Boolean.valueOf(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.INCLUDE_ATTRIBUTE)));
                spDO.setAttributeConsumingServiceIndex(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.CONSUMING_SERVICE_INDEX));
            }
            if (Boolean.valueOf(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.AUDIENCE_RESTRICTION)) &&
                    elem.getElementsByTagName(SAMLSSOConstants.FileBasedSPConfig.AUDIENCE_LIST) != null) {
                spDO.setRequestedAudiences(getTextValueList(elem, SAMLSSOConstants.FileBasedSPConfig.AUDIENCE));
            }
            if (Boolean.valueOf(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.RECIPIENT_VALIDATION)) &&
                    elem.getElementsByTagName(SAMLSSOConstants.FileBasedSPConfig.RECIPIENT_LIST) != null) {
                spDO.setRequestedRecipients(getTextValueList(elem, SAMLSSOConstants.FileBasedSPConfig.RECIPIENT));
            }

            if (Boolean.valueOf(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.ENABLE_IDP_INIT_SLO))) {
                spDO.setIdPInitSLOEnabled(true);
                if (elem.getElementsByTagName(SAMLSSOConstants.FileBasedSPConfig.RETURN_TO_URL_LIST) != null) {
                    List<String> sloReturnToUrls = new ArrayList<>();
                    for(String sloReturnUrl : getTextValueList(elem, SAMLSSOConstants
                            .FileBasedSPConfig.RETURN_TO_URL)) {
                        sloReturnToUrls.add(IdentityUtil.fillURLPlaceholders(sloReturnUrl));
                    }
                    spDO.setIdpInitSLOReturnToURLs(sloReturnToUrls);
                }
            }

            spDO.setDoSingleLogout(singleLogout);
            spDO.setDoSignAssertions(signAssertion);
            spDO.setDoValidateSignatureInRequests(validateSignature);
            spDO.setDoEnableEncryptedAssertion(encryptAssertion);
            spDO.setDoSignResponse(Boolean.valueOf(getTextValue(elem, SAMLSSOConstants
                    .FileBasedSPConfig.SIGN_RESPONSE)));
            spDO.setIdPInitSSOEnabled(Boolean.valueOf(getTextValue(elem, SAMLSSOConstants.FileBasedSPConfig.IDP_INIT)));
            serviceProviders[i] = spDO;
        }
        return serviceProviders;
    }

    /**
     *
     * Fills the certificate details such as the PEM content or the certificate alias from the SP file contents.
     *
     * @param spDO
     * @param element
     * @return true if the certificate details could be filled, false otherwise.
     */
    private boolean fillCertificateDetails(SAMLSSOServiceProviderDO spDO, Element element) {

        // Check whether there is an embedded certificate inside the SP file.
        // i.e the relevant file in repository/conf/identity/service-providers/
        try {
            ServiceProvider serviceProvider = SAMLSSOUtil.getApplicationMgtService()
                    .getServiceProviderByClientId(spDO.getIssuer(),
                            SAMLSSOConstants.INBOUND_AUTH_TYPE_SAML, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);

            String certificateContent = serviceProvider.getCertificateContent();

            if (certificateContent != null) {
                spDO.setX509Certificate((X509Certificate) IdentityUtil
                        .convertPEMEncodedContentToCertificate(certificateContent));

                if (log.isDebugEnabled()){
                    log.debug(String.format("An application certificate is available for the file based " +
                            "SAML service provider with the issuer name '%s'", spDO.getIssuer()));
                }

            } else {

                if (log.isDebugEnabled()){
                    log.debug(String.format("An application certificate is NOT available for the file based " +
                                    "SAML service provider with the issuer name '%s'. Alias will be considered",
                            spDO.getIssuer()));
                }

                // If not fallback for the alias defined in the entry of repository/conf/identity/sso-idp-config.xml.
                String certificateAlias = getTextValue(element, SAMLSSOConstants.FileBasedSPConfig.CERT_ALIAS);

                if (certificateAlias != null) {

                    if (log.isDebugEnabled()){
                        log.debug(String.format("A certificate alias is available for the file based " +
                                "SAML service provider with the issuer name '%s'", spDO.getIssuer()));
                    }

                    spDO.setX509Certificate(getCertificateFromKeyStore(certificateAlias));
                    spDO.setCertAlias(certificateAlias);
                }
            }

            if (spDO.getX509Certificate() == null) {
                String errorMessage = String.format("The file based SAML service provider with the " +
                        "issuer name '%s' is enabled for signature validation and/or assertion encryption. " +
                        "But a valid application certificate or a certificate alias has not been configured. " +
                        "The service provider will NOT be loaded.", spDO.getIssuer());
                log.error(errorMessage);
                return false;
            }

        } catch (IdentityApplicationManagementException | CertificateException e) {
            String errorMessage = String.format("An error occurred while retrieving the application " +
                    "certificate for file based SAML service provider with the issuer name '%s'. " +
                    "The service provider will NOT be loaded.", spDO.getIssuer());
            log.error(errorMessage);
            return false;
        }

        return true;
    }

    /**
     *
     * Retrieves and returns the certificate from keystore.
     *
     * @param alias
     * @return
     */
    private X509Certificate getCertificateFromKeyStore(String alias) {

        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID);
            KeyStore keyStore = keyStoreManager.getPrimaryKeyStore();
            X509Certificate certificate = (X509Certificate)keyStore.getCertificate(alias);
            return certificate;
        } catch (Exception e) {
            String errorMsg = String.format("Error occurred while retrieving the certificate for " +
                    "the alias '%s'." + alias);
            log.error(errorMsg);
            return null;
        }
    }

    /**
     * Read the element value for the given element
     *
     * @param element Parent element
     * @param tagName name of the child element
     * @return value of the element
     */
    private String getTextValue(Element element, String tagName) {
        String textVal = null;
        NodeList nl = element.getElementsByTagName(tagName);
        if (nl != null && nl.getLength() > 0) {
            Element el = (Element) nl.item(0);
            if (el != null) {
                String text = el.getTextContent();
                if (text != null && text.length() > 0) {
                    textVal = text;
                }
            }
        }
        return textVal;
    }

    private List<String> getTextValueList(Element element, String tagName) {
        List<String> textValList = new ArrayList<>();
        NodeList nl = element.getElementsByTagName(tagName);
        if (nl != null && nl.getLength() > 0) {
            for (int i = 0; i < nl.getLength(); i++) {
                Element el = (Element) nl.item(i);
                if (el != null) {
                    String text = el.getTextContent();
                    if (text != null && text.length() > 0) {
                        textValList.add(text);
                    }
                }
            }
        }
        return textValList;
    }

    /**
     * Check whether a given file exists in the system
     *
     * @param path file path
     * @return true, if file exists. False otherwise
     */
    private boolean isFileExisting(String path) {
        File file = new File(path);
        if (file.exists()) {
            return true;
        }
        return false;
    }


}
