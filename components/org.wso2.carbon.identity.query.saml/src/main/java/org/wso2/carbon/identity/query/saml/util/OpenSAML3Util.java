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
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.SAML2SSOFederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.query.saml.X509CredentialImpl;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.internal.SAMLQueryServiceComponent;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.internal.ServiceReferenceHolder;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import static org.opensaml.core.xml.util.XMLObjectSupport.buildXMLObject;

/**
 * This is a utility class for processing request message issuer and signature elements.
 */
public class OpenSAML3Util {

    private static final Log log = LogFactory.getLog(OpenSAML3Util.class);

    /**
     * this method is used to get issuer according to tenant domain.
     *
     * @param tenantDomain tenant domain of the issuer
     * @return Issuer  instance of Issuer
     * @throws IdentitySAML2QueryException If unable to connect with RealmService
     */
    public static Issuer getIssuer(String tenantDomain) throws IdentitySAML2QueryException {

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
                log.error("Error occurred while retrieving tenant id from tenant domain", e);
                throw new IdentitySAML2QueryException("Error occurred while retrieving tenant id from tenant domain");
            }

            if (MultitenantConstants.INVALID_TENANT_ID == tenantId) {
                log.error("Invalid tenant domain - '" + tenantDomain + "'");
                throw new IdentitySAML2QueryException("Error occurred while retrieving tenant id from tenant domain");
            }
        }

        try {
            IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            identityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            log.error("Error occurred while retrieving Resident Identity Provider information for tenant", e);
            throw new IdentitySAML2QueryException(
                    "Error occurred while retrieving Resident Identity Provider information for tenant " +
                            tenantDomain);
        } catch (IdentityException e) {
            log.error("Error occurred while retrieving Identity Provider Information for tenant", e);
            throw new IdentitySAML2QueryException("Error occurred while retrieving Identity Provider Information for tenant");
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
     * @throws IdentitySAML2QueryException If unable to write signature to the assertion
     */
    public static void setSignature(Assertion assertion, String signatureAlgorithm, String digestAlgorithm,
                                    X509Credential cred) throws IdentitySAML2QueryException {

        try {
            doSetSignature(assertion, signatureAlgorithm, digestAlgorithm, cred);
        } catch (IdentityException e) {
            log.error("Unable to set signature to the assertion id"+assertion.getID(),e);
            throw new IdentitySAML2QueryException("Unable to set signature to the assertion id"+assertion.getID(),e);
        }
    }

    /**
     * This method is used to set Signature to the Response message
     * @param response Genareated Response including zero or more assertions
     * @param signatureAlgorithm signature Algorithm
     * @param digestAlgorithm cryptographic hash algorithm
     * @param cred X509Credential instance
     * @return Response response message
     * @throws IdentitySAML2QueryException If unable to set signature to the response
     */
    public static Response setSignature(Response response, String signatureAlgorithm, String digestAlgorithm,
                                        X509Credential cred) throws IdentitySAML2QueryException {

        try {
            return (Response) doSetSignature(response, signatureAlgorithm, digestAlgorithm, cred);
        } catch (IdentityException e) {
            log.error("Unable to set signature to the response id:"+response.getID(),e);
            throw new IdentitySAML2QueryException("Unable to set signature to the response id:"+response.getID(),e);
        }
    }

    /**
     * Generic method to sign SAML2.0 Assertion or Response
     *
     * @param request            generic xml request
     * @param signatureAlgorithm signature algorithm
     * @param digestAlgorithm    cryptographic hash algorithm
     * @param cred               X509credential instance
     * @return SignableXMLObject signed XML object
     * @throws IdentitySAML2QueryException If unable to set signature
     */
    private static SignableXMLObject doSetSignature(SignableXMLObject request, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentitySAML2QueryException {
        try {
            SAMLQueryRequestUtil.doBootstrap();
            return setSSOSignature(request, signatureAlgorithm, digestAlgorithm, cred);


        } catch (IdentityException e) {
            log.error("Error while signing the XML object.", e);
            throw new IdentitySAML2QueryException("Error while signing the XML object.");
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
     * @throws IdentitySAML2QueryException If unable to set signature
     */
    public static SignableXMLObject setSSOSignature(SignableXMLObject signableXMLObject, String signatureAlgorithm, String
            digestAlgorithm, X509Credential cred) throws IdentitySAML2QueryException {
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
            log.error("Error occurred while retrieving encoded cert", e);
            throw new IdentitySAML2QueryException("Error occurred while retrieving encoded cert");
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
            log.error("Unable to marshall the request", e);
            throw new IdentitySAML2QueryException("Unable to marshall the request");
        }
        Init.init();
        try {
            Signer.signObjects(signatureList);
        } catch (SignatureException e) {
            log.error("Error occurred while signing request", e);
            throw new IdentitySAML2QueryException("Error occurred while signing request");
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
     * @throws IdentitySAML2QueryException When signature is invalid or unable to load credential information
     */
    public static boolean validateXMLSignature(RequestAbstractType request, String alias,
                                               String domainName) throws IdentitySAML2QueryException {
        boolean isSignatureValid = false;
        if (request.getSignature() != null) {
            try {
                X509Credential cred = OpenSAML3Util.getX509CredentialImplForTenant(domainName, alias);
                SignatureValidator.validate(request.getSignature(), cred);
                return true;
            } catch (SignatureException e) {
                log.error("Unable to validate Signature of the request id:"+request.getID()+" with alias:"
                        +alias+" ,domainname: "+domainName,e);
                throw  new IdentitySAML2QueryException("Unable to validate Signature of the request id:"+request.getID()+" with alias:"
                        +alias+" ,domainname: "+domainName,e);
            }
        }
        return isSignatureValid;
    }

    /**
     * Get the X509CredentialImpl object for a particular tenant
     *
     * @param tenantDomain tenant domain of the issuer
     * @param alias        alias of cert
     * @return X509CredentialImpl object containing the public certificate of that tenant
     * @throws IdentitySAML2QueryException Error when creating X509CredentialImpl object
     */
    public static X509CredentialImpl getX509CredentialImplForTenant(String tenantDomain, String alias)
            throws IdentitySAML2QueryException {
        if (tenantDomain.trim() == null || alias.trim() == null) {
            log.error("Invalid parameters; domain name : " + tenantDomain + ", " +
                    "alias : " + alias);
        }

        X509CredentialImpl credentialImpl = null;
        try {
            java.security.cert.X509Certificate cert =
                    (java.security.cert.X509Certificate) ServiceReferenceHolder.getKeyProvider()
                            .getCertificate(tenantDomain);
            credentialImpl = new X509CredentialImpl(cert);
        } catch (Exception e) {
            //keyStoreManager throws Exception
            log.error("Unable to load key store manager for the tenant domain:"+tenantDomain,e);
            throw new IdentitySAML2QueryException("Unable to load key store manager for the tenant domain:"+tenantDomain,e);
        }
        return credentialImpl;
    }


}
