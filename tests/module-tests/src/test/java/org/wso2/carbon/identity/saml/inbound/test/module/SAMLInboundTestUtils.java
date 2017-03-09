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

package org.wso2.carbon.identity.saml.inbound.test.module;

import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.Base64;
import org.osgi.framework.BundleContext;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.gateway.common.model.sp.ServiceProviderConfig;
import org.wso2.carbon.identity.gateway.store.ServiceProviderConfigStore;
import org.wso2.carbon.identity.saml.exception.SAMLServerException;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Utilities for SAML inbound tests.
 */
public class SAMLInboundTestUtils {

    private static Logger logger = LoggerFactory.getLogger(SAMLInboundTestUtils.class);

    public static HttpURLConnection request(String path, String method, boolean keepAlive) throws IOException {

        URL url = new URL(path);

        HttpURLConnection httpURLConnection = null;

        httpURLConnection = (HttpURLConnection) url.openConnection();

        httpURLConnection.setRequestMethod(method);
        if (!keepAlive) {
            httpURLConnection.setRequestProperty("CONNECTION", "CLOSE");
        }
        return httpURLConnection;

    }

    public static String getContent(HttpURLConnection urlConn) throws IOException {
        return new String(IOUtils.toByteArray(urlConn.getInputStream()), Charsets.UTF_8);
    }

    public static String getResponseHeader(String headerName, HttpURLConnection urlConnection) {
        return ((HttpURLConnection) urlConnection).getHeaderField(headerName);
    }


    public static Response getSAMLResponse(String samlResponse) throws SAMLServerException {
        String decodedResponse = new String(Base64.decode(samlResponse));
        XMLObject xmlObject = SAML2AuthUtils.unmarshall(decodedResponse);

        return (Response) xmlObject;
    }

    public static ServiceProviderConfig getServiceProviderConfigs(String uniqueId, BundleContext bundleContext) {
        ServiceProviderConfigStore serviceProviderConfigStore = bundleContext.getService(bundleContext
                .getServiceReference(ServiceProviderConfigStore.class));
        return serviceProviderConfigStore.getServiceProvider(uniqueId);
    }


    public static AuthnRequest buildAuthnRequest(String idpUrl, boolean isForce, boolean isPassive, String issuerName) {

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");

        String spEntityId = issuerName;
        issuer.setValue(spEntityId);

        DateTime issueInstant = new DateTime();

        AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authRequest = authRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
                "AuthnRequest", "samlp");
        authRequest.setForceAuthn(isForce);
        authRequest.setIsPassive(isPassive);
        authRequest.setIssueInstant(issueInstant);

        // how about redirect binding URI?
        authRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);

        String acsUrl = "http://localhost:8080/travelocity.com/home.jsp";
        authRequest.setAssertionConsumerServiceURL(acsUrl);
        authRequest.setIssuer(issuer);
        authRequest.setID(SAML2AuthUtils.createID());
        authRequest.setVersion(SAMLVersion.VERSION_20);
        authRequest.setDestination(idpUrl);

        String attributeConsumingServiceIndex = "2342342";
        if (StringUtils.isNotBlank(attributeConsumingServiceIndex)) {
            try {
                authRequest.setAttributeConsumingServiceIndex(Integer.valueOf(attributeConsumingServiceIndex));
            } catch (NumberFormatException e) {
                logger.error("Error while setting AttributeConsumingServiceIndex to SAMLRequest.", e);
            }
        }

        boolean includeNameIDPolicy = true;
        if (includeNameIDPolicy) {
            NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
            NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
            nameIdPolicy.setFormat(NameIDType.UNSPECIFIED);
            //nameIdPolicy.setSPNameQualifier("Issuer");
            nameIdPolicy.setAllowCreate(true);
            authRequest.setNameIDPolicy(nameIdPolicy);
        }

        buildRequestedAuthnContext(authRequest);

        // handle SAML2 extensions

        return authRequest;
    }

    public static void buildRequestedAuthnContext(AuthnRequest authnRequest) {

        RequestedAuthnContextBuilder requestedAuthnContextBuilder = null;
        RequestedAuthnContext requestedAuthnContext = null;

        String includeAuthnContext = "";
        requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
        requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder
                .buildObject(SAMLConstants.SAML20_NS,
                        AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME,
                        SAMLConstants.SAML20_PREFIX);

        String authnContext = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
        if (StringUtils.isNotBlank(authnContext)) {
            authnContextClassRef.setAuthnContextClassRef(authnContext);
        } else {
            authnContextClassRef.setAuthnContextClassRef(AuthnContext.PPT_AUTHN_CTX);
        }

        String authnContextComparison = "exact";
        if (StringUtils.isNotEmpty(authnContextComparison)) {
            if (AuthnContextComparisonTypeEnumeration.EXACT.toString().equalsIgnoreCase(
                    authnContextComparison)) {
                requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
            } else if (AuthnContextComparisonTypeEnumeration.MINIMUM.toString().equalsIgnoreCase(
                    authnContextComparison)) {
                requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
            } else if (AuthnContextComparisonTypeEnumeration.MAXIMUM.toString().equalsIgnoreCase(
                    authnContextComparison)) {
                requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MAXIMUM);
            } else if (AuthnContextComparisonTypeEnumeration.BETTER.toString().equalsIgnoreCase(
                    authnContextComparison)) {
                requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
            }
        } else {
            requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        }
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
        if (requestedAuthnContext != null) {
            authnRequest.setRequestedAuthnContext(requestedAuthnContext);
        }
    }
}
