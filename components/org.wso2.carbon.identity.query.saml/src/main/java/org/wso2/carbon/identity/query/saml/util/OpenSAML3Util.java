/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.query.saml.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.SAML2SSOFederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.query.saml.X509CredentialImpl;
import org.wso2.carbon.identity.query.saml.internal.SAMLQueryServiceComponent;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import static org.opensaml.core.xml.util.XMLObjectSupport.buildXMLObject;
import static org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil.generateKSNameFromDomainName;

/**
 * This is a utility class for processing request message issuer and signature elements.
 */
public class OpenSAML3Util {

    private static Log log = LogFactory.getLog(OpenSAML3Util.class);

    /**
     * this method is used to get issuer according to tenant domain.
     *
     * @param tenantDomain tenant domain of the issuer
     * @return Issuer  instance of Issuer
     * @throws IdentityException If unable to connect with RealmService
     */
    public static Issuer getIssuer(String tenantDomain) throws IdentityException {

        Issuer issuer = new IssuerBuilder().buildObject();
        String idPEntityId = null;
        IdentityProvider identityProvider;
        int tenantId;

        if (StringUtils.isEmpty(tenantDomain) || "null".equals(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
            tenantId = MultitenantConstants.SUPER_TENANT_ID;
        } else {
            try {
                tenantId = SAMLQueryServiceComponent.getRealmservice().getTenantManager().getTenantId(tenantDomain);
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
     * This method is used to set signature to a assertion
     *
     * @param assertion          created assertion need to sign
     * @param signatureAlgorithm signature algorithm
     * @param digestAlgorithm    cryptographic hash algorithm
     * @param cred               X509Credential instance
     * @throws IdentityException If unable to write signature to the assertion
     */
    public static void setSignature(Assertion assertion, String signatureAlgorithm, String digestAlgorithm,
                                    X509Credential cred) throws IdentityException {

        doSetSignature(assertion, signatureAlgorithm, digestAlgorithm, cred);
    }

    public static Response setSignature(Response response, String signatureAlgorithm, String digestAlgorithm,
                                        X509Credential cred) throws IdentityException {

        return (Response) doSetSignature(response, signatureAlgorithm, digestAlgorithm, cred);
    }

    /**
     * Generic method to sign SAML2.0 Assertion or Response
     *
     * @param request            generic xml request
     * @param signatureAlgorithm signature algorithm
     * @param digestAlgorithm    cryptographic hash algorithm
     * @param cred               X509credential instance
     * @return SignableXMLObject signed XML object
     * @throws IdentityException If unable to set signature
     */
    private static SignableXMLObject doSetSignature(SignableXMLObject request, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentityException {
        SAMLQueryRequestUtil.doBootstrap();
        try {

            return setSSOSignature(request, signatureAlgorithm, digestAlgorithm, cred);


        } catch (Exception e) {
            throw IdentityException.error("Error while signing the XML object.", e);
        }
    }

    /**
     * This method is used to sign XML object
     *
     * @param signableXMLObject  signable XML object
     * @param signatureAlgorithm signature algorithm
     * @param digestAlgorithm    cryptographic hash algorithm
     * @param cred               X509Credential instance
     * @return SignableXMLObject signed XML object
     * @throws IdentityException If unable to set signature
     */
    public static SignableXMLObject setSSOSignature(SignableXMLObject signableXMLObject, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentityException {

        Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(cred);
        signature.setSignatureAlgorithm(signatureAlgorithm);
        signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);


        try {
            KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
            X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);
            String value = org.apache.xml.security.utils.Base64.encode(cred.getEntityCertificate().getEncoded());
            cert.setValue(value);
            data.getX509Certificates().add(cert);
            keyInfo.getX509Datas().add(data);
            signature.setKeyInfo(keyInfo);
        } catch (CertificateEncodingException e) {
            throw IdentityException.error("Error occurred while retrieving encoded cert", e);
        }

        signableXMLObject.setSignature(signature);
        ((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(digestAlgorithm);

        List<Signature> signatureList = new ArrayList<Signature>();
        signatureList.add(signature);

        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(signableXMLObject);

        try {
            marshaller.marshall(signableXMLObject);
        } catch (MarshallingException e) {
            throw IdentityException.error("Unable to marshall the request", e);
        }

        Init.init();

        try {
            Signer.signObjects(signatureList);
        } catch (SignatureException e) {
            throw IdentityException.error("Error occurred while signing request", e);
        }

        return signableXMLObject;
    }

    /**
     * Validate the signature of an assertion
     *
     * @param request    SAML Assertion, this could be either a SAML Request or a
     *                   LogoutRequest
     * @param alias      Certificate alias against which the signature is validated.
     * @param domainName domain name of the subject
     * @return true, if the signature is valid.
     * @throws IdentityException When signature is invalid or unable to load credential information
     */
    public static boolean validateXMLSignature(RequestAbstractType request, String alias,
                                               String domainName) throws IdentityException {

        boolean isSignatureValid = false;

        if (request.getSignature() != null) {
            try {
                X509Credential cred = OpenSAML3Util.getX509CredentialImplForTenant(domainName, alias);

                SignatureValidator.validate(request.getSignature(), cred);
                return true;
            } catch (IdentitySAML2SSOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to construct the X509CredentialImpl for the alias " +
                            alias, e);
                }
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while validating XML signature.", e);
                }
            }
        }
        return isSignatureValid;
    }

    /**
     * Get the X509CredentialImpl object for a particular tenant
     *
     * @param tenantDomain tenant domain of the issuer
     * @param alias        alias of cert
     * @return X509CredentialImpl object containing the public certificate of
     * that tenant
     * @throws org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException Error when creating X509CredentialImpl object
     */
    public static X509CredentialImpl getX509CredentialImplForTenant(String tenantDomain, String alias)
            throws IdentitySAML2SSOException {

        if (tenantDomain.trim() == null || alias.trim() == null) {
            throw new IllegalArgumentException("Invalid parameters; domain name : " + tenantDomain + ", " +
                    "alias : " + alias);
        }
        int tenantId;
        try {
            tenantId = SAMLQueryServiceComponent.getRealmservice().getTenantManager().getTenantId(tenantDomain);
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
            } else {
                // for super tenant, load the default pub. cert using the
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


}
