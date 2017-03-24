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

import com.google.common.net.HttpHeaders;
import org.apache.commons.io.Charsets;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.CoreOptions;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerSuite;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.gateway.common.model.sp.ServiceProviderConfig;
import org.wso2.carbon.identity.saml.exception.SAML2SSOServerException;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.List;
import javax.inject.Inject;
import javax.ws.rs.HttpMethod;

/**
 * Tests for IDP initiated SAML.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class RequestSigningTests {

    private static final Logger log = LoggerFactory.getLogger(InitialTests.class);

    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;


    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = OSGiTestUtils.getDefaultSecurityPAXOptions();

        optionList.add(CoreOptions.systemProperty("java.security.auth.login.config")
                .value(Paths.get(OSGiTestUtils.getCarbonHome(), "conf", "security", "carbon-jaas.config")
                        .toString()));

        return optionList.toArray(new Option[optionList.size()]);
    }

    /**
     * Test authentication with post binding, request validation enabled.
     */
    @Test
    public void testRequestSigningWithPostBinding() {
        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        String authenticationReqSignedOriginalValue = serviceProviderConfig.getRequestValidationConfig()
                .getRequestValidatorConfigs().get(0).getProperties()
                .getProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED);
        serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED, "true");
        try {

            String requestRelayState = "6c72a926-119d-4b4d-b236-f7594a037b0e";

            AuthnRequest samlRequest = TestUtils.buildAuthnRequest("https://localhost:9292/gateway",
                    false, false, TestConstants.SAMPLE_ISSUER_NAME, TestConstants.ACS_URL);

            SAML2AuthUtils.setSignature(samlRequest, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3" +
                    ".org/2000/09/xmldsig#sha1", true, SAML2AuthUtils.getServerCredentials());

            String authnRequest = SAML2AuthUtils.encodeForPost((SAML2AuthUtils.marshall(samlRequest)));
            authnRequest = URLEncoder.encode(authnRequest);
            String postBody = TestConstants.SAML_REQUEST_PARAM + "=" + authnRequest + TestConstants
                    .QUERY_PARAM_SEPARATOR + TestConstants.RELAY_STATE + "=" + requestRelayState;

            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    , HttpMethod.POST, true);
            urlConnection.setDoOutput(true);
            urlConnection.getOutputStream().write(postBody.toString().getBytes(Charsets.UTF_8));
            String locationHeader = TestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(TestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(TestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(TestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(TestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = TestUtils.request
                    (TestConstants.GATEWAY_ENDPOINT + "?" + TestConstants.RELAY_STATE + "=" +
                            relayState + "&" + TestConstants.ASSERTION + "=" +
                            TestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            cookie = cookie.split(org.wso2.carbon.identity.gateway.common.util.Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
        } catch (IOException e) {
            Assert.fail("Error while running testSAMLInboundAuthenticationPost test case", e);
        } finally {
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED,
                            authenticationReqSignedOriginalValue);
        }
    }

    /**
     * Test authentication with post binding, request validation enabled.
     */
    @Test
    public void testInvalidSignatureWithPostBindingRequest() {
        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        String authenticationReqSignedOriginalValue = serviceProviderConfig.getRequestValidationConfig()
                .getRequestValidatorConfigs().get(0).getProperties()
                .getProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED);
        serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED, "true");
        try {

            String requestRelayState = "6c72a926-119d-4b4d-b236-f7594a037b0e";

            AuthnRequest samlRequest = TestUtils.buildAuthnRequest("https://localhost:9292/gateway",
                    false, false, TestConstants.SAMPLE_ISSUER_NAME, TestConstants.ACS_URL);

            SAML2AuthUtils.setSignature(samlRequest, "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3" +
                    ".org/2000/09/xmldsig#sha1", true, SAML2AuthUtils.getServerCredentials());

            samlRequest.getSignature().setSignatureAlgorithm(SAML2AuthConstants.XML.SignatureAlgorithmURI.RSA_SHA384);
            String authnRequest = SAML2AuthUtils.encodeForPost((SAML2AuthUtils.marshall(samlRequest)));
            authnRequest = URLEncoder.encode(authnRequest);
            String postBody = TestConstants.SAML_REQUEST_PARAM + "=" + authnRequest + TestConstants
                    .QUERY_PARAM_SEPARATOR + TestConstants.RELAY_STATE + "=" + requestRelayState;

            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    , HttpMethod.POST, true);
            urlConnection.setDoOutput(true);
            urlConnection.getOutputStream().write(postBody.toString().getBytes(Charsets.UTF_8));
            String response = TestUtils.getContent(urlConnection);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            try {
                Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                Assert.assertEquals(samlResponseObject.getStatus().getStatusMessage().getMessage(), "Signature validation for AuthnRequest failed.");
            } catch (SAML2SSOServerException e) {
                Assert.fail("Error while building response object", e);
            }
        } catch (IOException e) {
            Assert.fail("Error while running testSAMLInboundAuthenticationPost test case", e);
        } finally {
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED,
                            authenticationReqSignedOriginalValue);
        }
    }
    /**
     * SAML request without signature validation turned on.
     */
    @Test
    public void testSAMLAssertionWithoutRequestSignatureValidation() {
        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        try {
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED, "false");

            AuthnRequest samlRequest = TestUtils.buildAuthnRequest("https://localhost:9292/gateway",
                    false, false, TestConstants.SAMPLE_ISSUER_NAME, TestConstants.ACS_URL);
            String samlRequestString = SAML2AuthUtils.encodeForRedirect(samlRequest);
            SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlRequest));

            StringBuilder httpQueryString = new StringBuilder(SAML2AuthConstants.SAML_REQUEST + "=" + samlRequestString);
            httpQueryString.append("&" + SAML2AuthConstants.RELAY_STATE + "=" + URLEncoder.encode("relayState",
                    StandardCharsets.UTF_8.name()).trim());

            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    + "?" + httpQueryString.toString(), HttpMethod.GET, false);

            String locationHeader = TestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(TestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(TestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(TestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(TestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = TestUtils.request
                    (TestConstants.GATEWAY_ENDPOINT + "?" + TestConstants.RELAY_STATE + "=" +
                            relayState + "&" + TestConstants.ASSERTION + "=" +
                            TestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);

            cookie = cookie.split(org.wso2.carbon.identity.gateway.common.util.Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
            String response = TestUtils.getContent(urlConnection);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            try {
                Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                Assert.assertEquals(TestConstants.AUTHENTICATED_USER_NAME, samlResponseObject
                        .getAssertions().get(0).getSubject().getNameID().getValue());
            } catch (SAML2SSOServerException e) {
                log.error("Error while building response object from SAML response string", e);
            }

        } catch (IOException e) {
            Assert.fail("Error while running testSAMLAssertionWithoutRequestValidation test case");
        } finally {
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED, "true");
        }
    }

    /**
     * Test inbound authentication with redirect binding with invalid signature parameter.
     */
    @Test
    public void testAuthnRequestSignatureValidationWithInvalidSignatureForRedirect() {

        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED, "true");
        try {
            AuthnRequest samlRequest = TestUtils.buildAuthnRequest("https://localhost:9292/gateway",
                    false, false, TestConstants.SAMPLE_ISSUER_NAME,
                    TestConstants.ACS_URL);
            String samlRequestString = SAML2AuthUtils.encodeForRedirect(samlRequest);

            StringBuilder httpQueryString = new StringBuilder(SAML2AuthConstants.SAML_REQUEST + "=" + samlRequestString);
            httpQueryString.append("&" + SAML2AuthConstants.RELAY_STATE + "=" + URLEncoder.encode("relayState",
                    StandardCharsets.UTF_8.name()).trim());
            SAML2AuthUtils.addSignatureToHTTPQueryString(httpQueryString, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    SAML2AuthUtils.getServerCredentials());

            httpQueryString.replace(httpQueryString.indexOf("Signature=") + 10, httpQueryString.length(),
                    "invalid_signature");
            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    + "?" + httpQueryString.toString(), HttpMethod.GET, false);
            String postBody = TestUtils.getContent(urlConnection);
//          Relay state must be returned for error scenarios as well
//            Assert.assertTrue(postBody.contains(TestConstants.RELAY_STATE));

            Assert.assertEquals(urlConnection.getResponseCode(), 200);
            Assert.assertNotNull(postBody);
            String samlResponse = postBody.split("SAMLResponse' value='")[1].split("'>")[0];
            Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
            Assert.assertEquals(samlResponseObject.getAssertions().size(), 0);

        } catch (IOException e) {
            Assert.fail("Error while running testSAMLInboundAuthentication test case", e);
        } catch (SAML2SSOServerException e) {
            Assert.fail("Error while building response object", e);
        } finally {
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED, "false");
        }
    }

    /**
     * Test inbound authentication with redirect binding with invalid signature parameter.
     */
    @Test
    public void testAuthenticationSignatureValidationRedirectBinding() {

        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED, "true");
        try {
            AuthnRequest samlRequest = TestUtils.buildAuthnRequest("https://localhost:9292/gateway",
                    false, false, TestConstants.SAMPLE_ISSUER_NAME,
                    TestConstants.ACS_URL);
            String samlRequestString = SAML2AuthUtils.encodeForRedirect(samlRequest);

            StringBuilder httpQueryString = new StringBuilder(SAML2AuthConstants.SAML_REQUEST + "=" + samlRequestString);
            httpQueryString.append("&" + SAML2AuthConstants.RELAY_STATE + "=" + URLEncoder.encode("relayState",
                    StandardCharsets.UTF_8.name()).trim());
            SAML2AuthUtils.addSignatureToHTTPQueryString(httpQueryString, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    SAML2AuthUtils.getServerCredentials());

            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    + "?" + httpQueryString.toString(), HttpMethod.GET, false);
            String locationHeader = TestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(TestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(TestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(TestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(TestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = TestUtils.request
                    (TestConstants.GATEWAY_ENDPOINT + "?" + TestConstants.RELAY_STATE + "=" +
                            relayState + "&" + TestConstants.ASSERTION + "=" +
                            TestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);

            cookie = cookie.split(org.wso2.carbon.identity.gateway.common.util.Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
            String response = TestUtils.getContent(urlConnection);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            try {
                Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                Assert.assertEquals(TestConstants.AUTHENTICATED_USER_NAME, samlResponseObject
                        .getAssertions().get(0).getSubject().getNameID().getValue());
            } catch (SAML2SSOServerException e) {
                log.error("Error while building response object from SAML response string", e);
            }

        } catch (IOException e) {
            Assert.fail("Error while running testSAMLInboundAuthentication test case", e);
        } finally {
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.AUTHN_REQUEST_SIGNED, "false");
        }
    }



}
