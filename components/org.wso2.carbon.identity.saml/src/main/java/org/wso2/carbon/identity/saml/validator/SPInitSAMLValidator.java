/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.saml.validator;

import org.apache.commons.lang.StringUtils;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.gateway.api.context.GatewayMessageContext;
import org.wso2.carbon.identity.gateway.common.model.sp.RequestValidatorConfig;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.saml.builders.X509CredentialImpl;
import org.wso2.carbon.identity.saml.builders.signature.DefaultSSOSigner;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.exception.SAMLRequestValidatorException;
import org.wso2.carbon.identity.saml.exception.SAMLServerException;
import org.wso2.carbon.identity.saml.model.SAMLConfigurations;
import org.wso2.carbon.identity.saml.model.SAMLValidatorConfig;
import org.wso2.carbon.identity.saml.request.SAMLSPInitRequest;
import org.wso2.carbon.identity.saml.util.SAML2URI;
import org.wso2.carbon.identity.saml.util.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class SPInitSAMLValidator extends SAMLValidator {

    private static Logger log = LoggerFactory.getLogger(SPInitSAMLValidator.class);

    /**
     * Build a criteria set suitable for input to the trust engine.
     *
     * @param issuer
     * @return
     * @throws SecurityPolicyException
     */
    private static CriteriaSet buildCriteriaSet(String issuer) {
        CriteriaSet criteriaSet = new CriteriaSet();
        if (!DatatypeHelper.isEmpty(issuer)) {
            criteriaSet.add(new EntityIDCriteria(issuer));
        }
        criteriaSet.add(new UsageCriteria(UsageType.SIGNING));
        return criteriaSet;
    }

    /**
     * @param sigAlg
     * @return
     * @throws SecurityPolicyException
     */
    private static String getSigAlg(String sigAlg) throws SecurityPolicyException {
        if (StringUtils.isEmpty(sigAlg)) {
            throw new SecurityPolicyException("Could not extract Signature Algorithm from query string");
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
     * @param signature
     * @return
     * @throws SecurityPolicyException
     */
    protected static byte[] getSignature(String signature) throws SecurityPolicyException {
        if (StringUtils.isEmpty(signature)) {
            throw new SecurityPolicyException("Could not extract the Signature from query string");
        }
        return Base64.decode(signature);
    }

    /**
     * @param request
     * @return
     * @throws SecurityPolicyException
     */
    protected static byte[] getSignedContent(SAMLSPInitRequest request) throws SecurityPolicyException {
        // We need the raw non-URL-decoded query string param values for
        // HTTP-Redirect DEFLATE simple signature
        // validation.
        // We have to construct a string containing the signature input by
        // accessing the
        // request directly. We can't use the decoded parameters because we need
        // the raw
        // data and URL-encoding isn't canonical.
        if (log.isDebugEnabled()) {
            log.debug("Constructing signed content string from URL query string " + request.getQueryString());
        }
        String constructed = buildSignedContentString(request.getQueryString());
        if (DatatypeHelper.isEmpty(constructed)) {
            throw new SecurityPolicyException(
                    "Could not extract signed content string from query string");
        }
        if (log.isDebugEnabled()) {
            log.debug("Constructed signed content string for HTTP-Redirect DEFLATE " + constructed);
        }
        try {
            return constructed.getBytes(StandardCharsets.UTF_8.name());
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
     * @param queryString
     *         the raw HTTP query string from the request
     * @return a string representation of the signed content
     * @throws SecurityPolicyException
     *         thrown if there is an error during request processing
     */
    private static String buildSignedContentString(String queryString) throws SecurityPolicyException {
        StringBuilder builder = new StringBuilder();

        // One of these two is mandatory
        if (!appendParameter(builder, queryString, "SAMLRequest") && !appendParameter(builder, queryString,
                                                                                      "SAMLResponse")) {
            throw new SecurityPolicyException(
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
     * @param builder
     *         string builder to which to append the parameter
     * @param queryString
     *         the URL query string containing parameters
     * @param paramName
     *         the name of the parameter to append
     * @return true if parameter was found, false otherwise
     */
    private static boolean appendParameter(StringBuilder builder, String queryString,
                                           String paramName) {
        String rawParam = HTTPTransportUtils.getRawQueryStringParameter(queryString, paramName);
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
    public boolean canHandle(MessageContext messageContext) {
        if (messageContext instanceof GatewayMessageContext) {
            GatewayMessageContext gatewayMessageContext = (GatewayMessageContext) messageContext;
            if (gatewayMessageContext.getIdentityRequest() instanceof SAMLSPInitRequest) {
                return true;
            }
        }
        return false;
    }

    public String getName() {
        return "SPInitSAMLValidator";
    }

    public int getPriority(MessageContext messageContext) {
        return 10;
    }

    @Override
    public GatewayHandlerResponse validate(AuthenticationContext authenticationContext)
            throws SAMLRequestValidatorException {

        initSAMLMessageContext(authenticationContext);
        SAMLSPInitRequest identityRequest = (SAMLSPInitRequest) authenticationContext.getIdentityRequest();
        String decodedRequest;


        if (identityRequest.isRedirect()) {
            decodedRequest = SAMLSSOUtil.SAMLAssertion.decode(identityRequest.getSAMLRequest());
        } else {
            decodedRequest = SAMLSSOUtil.SAMLAssertion.decodeForPost(identityRequest.getSAMLRequest());
        }
        XMLObject request = SAMLSSOUtil.SAMLAssertion.unmarshall(decodedRequest);

        if (request instanceof AuthnRequest) {

            authenticationContext.setUniqueId(((AuthnRequest) request).getIssuer().getValue());
            SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext
                    .getParameter(SAMLSSOConstants.SAMLContext);

            issuerValidate(authenticationContext);

            RequestValidatorConfig validatorConfig = getValidatorConfig(authenticationContext);
            updateValidatorConfig(validatorConfig, authenticationContext);
            messageContext.getSamlValidatorConfig().getAssertionConsumerUrlList();
            messageContext.setDestination(((AuthnRequest) request).getDestination());
            messageContext.setId(((AuthnRequest) request).getID());
            messageContext.setAssertionConsumerUrl(((AuthnRequest) request).getAssertionConsumerServiceURL());
            messageContext.setIsPassive(((AuthnRequest) request).isPassive());
            if (samlAssetionValidation((AuthnRequest) request, messageContext)) {
                return GatewayHandlerResponse.CONTINUE;
            }
        }


        throw new SAMLRequestValidatorException("Error while validating saml request");
    }

    /**
     * @param request
     * @param issuer
     * @param alias
     * @param domainName
     * @return
     * @throws SecurityException
     * @throws SAMLServerException
     */
    public boolean validateSignature(SAMLSPInitRequest request, String issuer, String alias,
                                     String domainName) throws SecurityException,
                                                               SAMLServerException {

        byte[] signature = getSignature(request.getSignature());
        byte[] signedContent = getSignedContent(request);
        String algorithmUri = getSigAlg(request.getSignatureAlgorithm());
        CriteriaSet criteriaSet = buildCriteriaSet(issuer);

        // creating the SAML2HTTPRedirectDeflateSignatureRule
        X509CredentialImpl credential =
                SAMLSSOUtil.getX509CredentialImplForTenant(alias);
        List<Credential> credentials = new ArrayList<Credential>();
        credentials.add(credential);
        CollectionCredentialResolver credResolver = new CollectionCredentialResolver(credentials);
        KeyInfoCredentialResolver kiResolver = SecurityHelper.buildBasicInlineKeyInfoResolver();
        SignatureTrustEngine engine = new ExplicitKeySignatureTrustEngine(credResolver, kiResolver);
        return engine.validate(signature, signedContent, algorithmUri, criteriaSet, null);
    }

    protected boolean samlAssetionValidation(AuthnRequest authnReq, SAMLMessageContext messageContext)
            throws SAMLRequestValidatorException {

        // When this method is called, A SAML service provider with the given issuer should exist.Otherwise this
        // method is not getting called.

        if (!(SAMLVersion.VERSION_20.equals(authnReq.getVersion()))) {
            messageContext.setValid(false);
            String message = "Invalid SAML Version in Authentication Request. SAML Version should be equal to 2.0";
            throw new SAMLRequestValidatorException(new SAMLRequestValidatorException.SAMLErrorInfo(
                    SAML2URI.STATUS_CODE_VERSION_MISMATCH, message, messageContext.getAssertionConsumerURL()));
        }

        Issuer issuer = authnReq.getIssuer();
        if (StringUtils.isNotBlank(issuer.getValue())) {
            messageContext.setIssuer(issuer.getValue());
        } else if (StringUtils.isNotBlank(issuer.getSPProvidedID())) {
            messageContext.setIssuer(issuer.getSPProvidedID());
        }

        // Issuer Format attribute
        if ((StringUtils.isNotBlank(issuer.getFormat())) &&
            !(issuer.getFormat().equals(SAMLSSOConstants.Attribute.ISSUER_FORMAT))) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid Issuer Format attribute value " + issuer.getFormat());
            }
            messageContext.setValid(false);
            throw new SAMLRequestValidatorException(
                    SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                                                                            .REQUESTOR_ERROR,
                                                                    "Issuer Format attribute"
                                                                    + " value is invalid",
                                                                    authnReq
                                                                            .getAssertionConsumerServiceURL()));
        }

        SAMLValidatorConfig samlValidatorConfig = messageContext.getSamlValidatorConfig();
        // Check for a Spoofing attack
        String acsUrl = authnReq.getAssertionConsumerServiceURL();
        boolean acsValidated = false;
        acsValidated = SAMLSSOUtil.validateACS(messageContext.getIssuer(), authnReq
                .getAssertionConsumerServiceURL());

        if (!acsValidated) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid ACS URL value " + acsUrl + " in the AuthnRequest message from " + samlValidatorConfig
                        .getIssuer() + "\n" + "Possibly an attempt for a spoofing attack from Provider " +
                          authnReq.getIssuer().getValue());
            }
            messageContext.setValid(false);
            throw new SAMLRequestValidatorException(
                    SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                                                                            .REQUESTOR_ERROR,
                                                                    "Invalid Assertion "
                                                                    + "Consumer Service URL "
                                                                    + "in the "
                                                                    + "Authentication "
                                                                    +
                                                                    "Request" + ".", acsUrl));
        }


        //TODO : Validate the NameID Format
        Subject subject = authnReq.getSubject();
        if (subject != null && subject.getNameID() != null) {
            messageContext.setSubject(subject.getNameID().getValue());
        }

        // subject confirmation should not exist
        if (subject != null && subject.getSubjectConfirmations() != null &&
            !subject.getSubjectConfirmations().isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid Request message. A Subject confirmation method found " + subject
                        .getSubjectConfirmations().get(0));
            }
            messageContext.setValid(false);
            throw new SAMLRequestValidatorException(
                    SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                                                                            .REQUESTOR_ERROR,
                                                                    "Subject Confirmation "
                                                                    + "methods should NOT be "
                                                                    + "in the request.",
                                                                    authnReq
                                                                            .getAssertionConsumerServiceURL()));
        }
        messageContext.addParameter("forceAuth", authnReq.isForceAuthn());
        messageContext.addParameter("passiveAuth", authnReq.isPassive());
        Integer index = authnReq.getAttributeConsumingServiceIndex();
        //according the spec, should be an unsigned short
        if (index != null && !(index < 1)) {
            messageContext.setAttributeConsumingServiceIndex(index);
        }
        if (log.isDebugEnabled()) {
            log.debug("Authentication Request Validation is successful.");
        }

        if (samlValidatorConfig.isDoValidateSignatureInRequests()) {
            // TODO
            List<String> idpUrlSet = SAMLConfigurations.getInstance().getDestinationUrls();

            if (messageContext.getDestination() == null || !idpUrlSet.contains(messageContext.getDestination())) {
                String msg = "Destination validation for Authentication Request failed. " + "Received: [" +
                             messageContext.getDestination() + "]." + " Expected one in the list: [" + StringUtils
                                     .join(idpUrlSet, ',') + "]";
                if (log.isDebugEnabled()) {
                    log.debug(msg);
                }
                throw new SAMLRequestValidatorException(
                        SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                                                                                .REQUESTOR_ERROR, msg,
                                                                        authnReq.getAssertionConsumerServiceURL()));
            }

            // samlAssetionValidation the signature
            boolean isSignatureValid = validateAuthnRequestSignature(messageContext);

            if (!isSignatureValid) {
                String msg = "Signature validation for Authentication Request failed.";
                if (log.isDebugEnabled()) {
                    log.debug(msg);
                }
                messageContext.setValid(false);
                throw new SAMLRequestValidatorException(SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse(SAMLSSOConstants
                                                                                                                .StatusCodes
                                                                                                                .REQUESTOR_ERROR, msg,
                                                                                                        authnReq.getAssertionConsumerServiceURL()));
            }
        } else {
            //Validate the assertion consumer url,  only if request is not signed.
            String acsUrlFromMessageContext = messageContext.getAssertionConsumerURL();
            if (StringUtils.isBlank(acsUrlFromMessageContext) || !samlValidatorConfig.getAssertionConsumerUrlList()
                    .contains
                            (acsUrlFromMessageContext)) {
                String msg = "ALERT: Invalid Assertion Consumer URL value '" + acsUrlFromMessageContext + "' in the " +
                             "AuthnRequest message from  the issuer '" + samlValidatorConfig.getIssuer() +
                             "'. Possibly " + "an attempt for a spoofing attack";
                if (log.isDebugEnabled()) {
                    log.debug(msg);
                }
                messageContext.setValid(false);
                throw new SAMLRequestValidatorException(
                        SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                                                                                .REQUESTOR_ERROR, msg,
                                                                        authnReq.getAssertionConsumerServiceURL()));
            }
        }
        messageContext.setValid(true);
        return true;
    }

    protected boolean validateAuthnRequestSignature(SAMLMessageContext messageContext) {

        if (log.isDebugEnabled()) {
            log.debug("Validating SAML Request signature");
        }

        SAMLValidatorConfig samlValidatorConfig = messageContext.getSamlValidatorConfig();

        String alias = samlValidatorConfig.getCertAlias();
        RequestAbstractType request = null;
        SAMLSPInitRequest samlspInitRequest = (SAMLSPInitRequest) messageContext.getIdentityRequest();
        String decodedReq = null;

        if (samlspInitRequest.isRedirect()) {
            decodedReq = SAMLSSOUtil
                    .SAMLAssertion.decode(((SAMLSPInitRequest) messageContext.getIdentityRequest())
                                                  .getSAMLRequest());
        } else {
            decodedReq = SAMLSSOUtil.SAMLAssertion
                    .decodeForPost(((SAMLSPInitRequest) messageContext.getIdentityRequest())
                                           .getSAMLRequest());
        }
        request = (RequestAbstractType) SAMLSSOUtil.SAMLAssertion.unmarshall(decodedReq);

        try {
            if (samlspInitRequest.isRedirect()) {
                // DEFLATE signature in Redirect Binding
                return validateDeflateSignature((SAMLSPInitRequest) messageContext.getIdentityRequest(), messageContext
                        .getIssuer(), alias, "");
            } else {
                // XML signature in SAML Request message for POST Binding
                return validateXMLSignature(request, alias, "");
            }
        } catch (IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Signature Validation failed for the SAMLRequest : Failed to samlAssetionValidation the SAML "
                        + "Assertion",
                        e);
            }
            return false;
        }
    }

    protected boolean validateDeflateSignature(SAMLSPInitRequest request, String issuer,
                                             String alias, String domainName) throws IdentityException {
        try {
            return validateSignature(request, issuer,
                                     alias, domainName);
        } catch (org.opensaml.xml.security.SecurityException e) {
            log.error("Error validating deflate signature", e);
            return false;
        } catch (SAMLServerException e) {
            log.warn(
                    "Signature validation failed for the SAML Message : Failed to construct the X509CredentialImpl "
                    + "for the alias "
                    +
                    alias, e);
            return false;
        }
    }

    /**
     * Validate the signature of an assertion
     *
     * @param request
     *         SAML Assertion, this could be either a SAML Request or a LogoutRequest
     * @param alias
     *         Certificate alias against which the signature is validated.
     * @param domainName
     *         domain name of the subject
     * @return true, if the signature is valid.
     */
    protected boolean validateXMLSignature(RequestAbstractType request, String alias,
                                         String domainName) throws IdentityException {

        if (request.getSignature() != null) {
            try {
                X509Credential cred = SAMLSSOUtil.getX509CredentialImplForTenant(alias);
                return new DefaultSSOSigner().validateXMLSignature(request, cred, alias);
            } catch (SAMLServerException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature validation failed for the SAML Message : Failed to construct the " +
                              "X509CredentialImpl for the alias " + alias, e);
                }
            } catch (IdentityException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Validation Failed for the SAML Assertion : Signature is invalid.", e);
                }
            }
        }
        return false;
    }
}
