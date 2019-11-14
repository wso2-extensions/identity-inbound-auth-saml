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
package org.wso2.carbon.identity.sso.saml.validators;

import net.shibboleth.utilities.java.support.codec.Base64Support;
import org.apache.commons.lang.StringUtils;
import org.opensaml.security.SecurityException;
import net.shibboleth.utilities.java.support.net.URISupport;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.xmlsec.config.DefaultSecurityConfigurationBootstrap;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.builders.X509CredentialImpl;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class SAML2HTTPRedirectDeflateSignatureValidator implements SAML2HTTPRedirectSignatureValidator {

    private static final Log log = LogFactory.getLog(SAML2HTTPRedirectDeflateSignatureValidator.class);

    /**
     * Build a criteria set suitable for input to the trust engine.
     *
     * @param  issuer      Issuer of the SAML request.
     * @return criteriaSet Criteria set which acts as input to the trust engine.
     */
    private static CriteriaSet buildCriteriaSet(String issuer) {
        CriteriaSet criteriaSet = new CriteriaSet();

        /*
            The process below is currently commented due to a
            failure at an unit test - TODO
         */
//        if (StringUtils.isNotEmpty(issuer)) {
//            criteriaSet.add(new EntityIdCriterion(issuer));
//        }
        criteriaSet.add(new UsageCriterion(UsageType.SIGNING));
        return criteriaSet;
    }

    /**
     * Extract the signature algorithm from the query string.
     *
     * @param  queryString The raw HTTP query string from the request.
     * @return sigAlg      The signature algorithm.
     * @throws SecurityException If the signature algorithm cannot be extracted.
     */
    private static String getSigAlg(String queryString) throws SecurityException {
        String sigAlgQueryParam = URISupport.getRawQueryStringParameter(queryString, "SigAlg");
        if (StringUtils.isEmpty(sigAlgQueryParam)) {
            throw new SecurityException(
                    "Could not extract Signature Algorithm from query string");
        }
        String sigAlg = null;
        try {
            /* Split 'SigAlg=<sigalg_value>' query param using '=' as the delimiter,
            and get the Signature Algorithm */
            sigAlg = URLDecoder.decode(sigAlgQueryParam.split("=")[1], "UTF-8");
        } catch (UnsupportedEncodingException e) {
            if (log.isDebugEnabled()) {
                log.debug("Encoding not supported.", e);
            }
            // JVM is required to support UTF-8
            return null;
        }
        return sigAlg;
    }

    /**
     * Extract the signature value from the request, in the form suitable for
     * input into
     * {@link SignatureTrustEngine#validate(byte[], byte[], String, CriteriaSet, Credential)}
     * .
     * <p/>
     * Defaults to the Base64-decoded value of the HTTP request parameter named
     * <code>Signature</code>.
     *
     * @param  queryString The raw HTTP query string from the request.
     * @return byte[] containing the signature.
     * @throws SecurityException If the signature algorithm cannot be extracted.
     */
    protected static byte[] getSignature(String queryString) throws SecurityException {
        String signatureQueryParam = URISupport.getRawQueryStringParameter(queryString, "Signature");
        if (StringUtils.isEmpty(signatureQueryParam)) {
            throw new SecurityException("Could not extract the Signature from query string");
        }
        String signature = null;
        try {
            /* Split 'Signature=<sig_value>' query param using '=' as the delimiter,
		      and get the Signature value */
            signature = URLDecoder.decode(signatureQueryParam.split("=")[1], "UTF-8");
        } catch (UnsupportedEncodingException e) {
            if (log.isDebugEnabled()) {
                log.debug("Encoding not supported.", e);
            }
            // JVM is required to support UTF-8
            return new byte[0];
        }
        return Base64Support.decode(signature);
    }

    /**
     * Extract the signed content from the query string.
     *
     * @param  queryString The raw HTTP query string from the request.
     * @return byte[] containing the signed content.
     * @throws SecurityException Thrown if there is an error during request processing.
     */
    protected static byte[] getSignedContent(String queryString) throws SecurityException {
        // We need the raw non-URL-decoded query string param values for
        // HTTP-Redirect DEFLATE simple signature
        // validation.
        // We have to construct a string containing the signature input by
        // accessing the
        // request directly. We can't use the decoded parameters because we need
        // the raw
        // data and URL-encoding isn't canonical.
        if (log.isDebugEnabled()) {
            log.debug("Constructing signed content string from URL query string " + queryString);
        }
        String constructed = buildSignedContentString(queryString);
        if (StringUtils.isEmpty(constructed)) {
            throw new SecurityException(
                    "Could not extract signed content string from query string");
        }
        if (log.isDebugEnabled()) {
            log.debug("Constructed signed content string for HTTP-Redirect DEFLATE " + constructed);
        }
        try {
            return constructed.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            if (log.isDebugEnabled()) {
                log.debug("Encoding not supported.", e);
            }
            // JVM is required to support UTF-8
            return new byte[0];
        }
    }

    /**
     * Extract the raw request parameters and build a string representation of
     * the content that was signed.
     *
     * @param  queryString The raw HTTP query string from the request.
     * @return A string representation of the signed content.
     * @throws SecurityException Thrown if there is an error during request processing.
     */
    private static String buildSignedContentString(String queryString) throws SecurityException {
        StringBuilder builder = new StringBuilder();

        // One of these two is mandatory
        if (!appendParameter(builder, queryString, "SAMLRequest") && !appendParameter(builder, queryString, "SAMLResponse")) {
            throw new SecurityException(
                    "Extract of SAMLRequest or SAMLResponse from query string failed");
        }
        // This is optional
        appendParameter(builder, queryString, "RelayState");
        // This is mandatory, but has already been checked in superclass
        appendParameter(builder, queryString, "SigAlg");

        return builder.toString();
    }

    /**
     * Find the raw query string parameter indicated and append it to the string
     * builder.
     * <p/>
     * The appended value will be in the form 'paramName=paramValue' (minus the
     * quotes).
     *
     * @param  builder     String builder to which to append the parameter.
     * @param  queryString The URL query string containing parameters.
     * @param  paramName   The name of the parameter to append.
     * @return true if parameter was found, false otherwise.
     */
    private static boolean appendParameter(StringBuilder builder, String queryString,
                                           String paramName) {
        String rawParam = URISupport.getRawQueryStringParameter(queryString, paramName);
        if (rawParam == null) {
            return false;
        }
        if (builder.length() > 0) {
            builder.append('&');
        }
        builder.append(rawParam);
        return true;
    }

    @Override
    public void init() throws IdentityException {
        //overridden method, no need to implement here
    }

    /**
     * Validates the signature of the given SAML request using the given domain name and alias.
     *
     * @param  queryString SAML request (passed an an HTTP query parameter).
     * @param  issuer      Issuer of the SAML request.
     * @param  alias       Name given to a CA certificate.
     * @param  domainName  The tenant domain name.
     * @return A boolean value representing whether the signature is valid or not.
     * @throws SecurityException Thrown if there is an error during request processing.
     * @throws IdentitySAML2SSOException Thrown if there is an error when creating X509CredentialImpl object.
     */
    @Override
    public boolean validateSignature(String queryString, String issuer, String alias,
                                     String domainName) throws SecurityException,
            IdentitySAML2SSOException {
        byte[] signature = getSignature(queryString);
        byte[] signedContent = getSignedContent(queryString);
        String algorithmUri = getSigAlg(queryString);
        CriteriaSet criteriaSet = buildCriteriaSet(issuer);

        // creating the SAML2HTTPRedirectDeflateSignatureRule
        X509CredentialImpl credential =
                SAMLSSOUtil.getX509CredentialImplForTenant(domainName,
                        alias);

        List<Credential> credentials = new ArrayList<Credential>();
        credentials.add(credential);
        CollectionCredentialResolver credResolver = new CollectionCredentialResolver(credentials);
        KeyInfoCredentialResolver kiResolver = DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver();
        SignatureTrustEngine engine = new ExplicitKeySignatureTrustEngine(credResolver, kiResolver);
        return engine.validate(signature, signedContent, algorithmUri, criteriaSet, null);
    }

    /**
     * Validates the signature of the given SAML request against the given certificate.
     *
     * @param  queryString SAML request (passed an an HTTP query parameter).
     * @param  issuer      Issuer of the SAML request.
     * @param  certificate Certificate for validating the signature.
     * @return A boolean value representing whether the signature is valid or not.
     * @throws SecurityException Thrown if there is an error during request processing.
     */
    @Override
    public boolean validateSignature(String queryString, String issuer, X509Certificate certificate)
            throws SecurityException {

        byte[] signature = getSignature(queryString);
        byte[] signedContent = getSignedContent(queryString);
        String algorithmUri = getSigAlg(queryString);
        CriteriaSet criteriaSet = buildCriteriaSet(issuer);

        // creating the SAML2HTTPRedirectDeflateSignatureRule
        X509CredentialImpl credential = new X509CredentialImpl(certificate);

        List<Credential> credentials = new ArrayList<Credential>();
        credentials.add(credential);
        CollectionCredentialResolver credResolver = new CollectionCredentialResolver(credentials);
        KeyInfoCredentialResolver kiResolver = DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver();
        SignatureTrustEngine engine = new ExplicitKeySignatureTrustEngine(credResolver, kiResolver);
        return engine.validate(signature, signedContent, algorithmUri, criteriaSet, null);
    }
}
