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
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
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
import org.wso2.carbon.identity.gateway.api.exception.GatewayException;
import org.wso2.carbon.identity.gateway.common.model.sp.ServiceProviderConfig;
import org.wso2.carbon.identity.gateway.common.util.Constants;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.exception.ResponseHandlerException;
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.exception.SAMLServerException;
import org.wso2.carbon.identity.saml.request.SAMLRequest;
import org.wso2.carbon.identity.saml.request.SAMLSPInitRequest;
import org.wso2.carbon.identity.saml.response.SAMLLoginResponse;
import org.wso2.carbon.identity.saml.response.SAMLSPInitResponseHandler;
import org.wso2.carbon.identity.saml.util.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;

import javax.inject.Inject;
import javax.ws.rs.HttpMethod;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.file.Paths;
import java.util.List;

/**
 * General tests for SAML inbound SP Init.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class SAMLInboundSPInitTests {

    private static final Logger log = LoggerFactory.getLogger(SAMLInboundSPInitTests.class);

    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;


    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = SAMLInboundOSGiTestUtils.getDefaultSecurityPAXOptions();

        optionList.add(CoreOptions.systemProperty("java.security.auth.login.config")
                .value(Paths.get(SAMLInboundOSGiTestUtils.getCarbonHome(), "conf", "security", "carbon-jaas.config")
                        .toString()));

        return optionList.toArray(new Option[optionList.size()]);
    }

    /**
     * Test inbound authentication and successful statement on assertion.
     */
    @Test
    public void testSAMLInboundAuthentication() {
        try {
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + SAMLInboundTestConstants
                    .SAML_REQUEST, HttpMethod.GET, false);
            String locationHeader = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(SAMLInboundTestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = SAMLInboundTestUtils.request
                    (SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" + SAMLInboundTestConstants.RELAY_STATE + "=" + relayState +
                            "&" + SAMLInboundTestConstants.ASSERTION + "=" +
                            SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
        } catch (IOException e) {
            Assert.fail("Error while running testSAMLInboundAuthentication test case", e);
        }
    }

    /**
     * Test authentication with post binding.
     */
    @Test
    public void testSAMLInboundAuthenticationPost() {
        try {

            String requestRelayState = "6c72a926-119d-4b4d-b236-f7594a037b0e";
            String postBody = SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + URLEncoder.encode
                    (SAMLInboundTestConstants.SAML_POST_REQUEST) + SAMLInboundTestConstants
                    .QUERY_PARAM_SEPARATOR + SAMLInboundTestConstants
                    .RELAY_STATE + "=" + requestRelayState;

            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    , HttpMethod.POST, true);
            urlConnection.setDoOutput(true);
            urlConnection.getOutputStream().write(postBody.toString().getBytes(Charsets.UTF_8));
            String locationHeader = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(SAMLInboundTestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = SAMLInboundTestUtils.request
                    (SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" + SAMLInboundTestConstants.RELAY_STATE + "=" +
                            relayState + "&" + SAMLInboundTestConstants.ASSERTION + "=" +
                            SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
        } catch (IOException e) {
            Assert.fail("Error while running testSAMLInboundAuthenticationPost test case", e);
        }
    }

    /**
     * Testing the content of the SAML response.
     */
    @Test
    public void testSAMLResponse() {
        try {
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + SAMLInboundTestConstants
                    .SAML_REQUEST, HttpMethod.GET, false);
            String locationHeader = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(SAMLInboundTestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = SAMLInboundTestUtils.request
                    (SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" + SAMLInboundTestConstants.RELAY_STATE + "=" +
                            relayState + "&" + SAMLInboundTestConstants.ASSERTION + "=" +
                            SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            if (cookie != null) {
                cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
                Assert.assertNotNull(cookie);
                String response = SAMLInboundTestUtils.getContent(urlConnection);
                if (response != null) {
                    String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
                    try {
                        Response samlResponseObject = SAMLInboundTestUtils.getSAMLResponse(samlResponse);
                        Assert.assertEquals(SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, samlResponseObject
                                .getAssertions().get(0).getSubject().getNameID().getValue());
                    } catch (SAMLServerException e) {
                        Assert.fail("Error while building response object", e);
                    }
                }
            }
        } catch (IOException e) {
            Assert.fail("Error while running testSAMLResponse test case", e);
        }
    }

    /**
     * Sending out a request with wrong signature and asserting on response.
     */
    @Test
    public void testSAMLResponseWithWrongSignature() {
        try {
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + SAMLInboundTestConstants
                    .SAML_REQUEST_INVALID_SIGNATURE, HttpMethod.GET, false);
            //TODO : get proper error response after fixing error handling and then assert
            urlConnection.getResponseCode();

        } catch (IOException e) {
            Assert.fail("Error while running testSAMLResponseWithWrongSignature test case", e);
        }
    }

    /**
     * Sending out an authentication request without issuer and assert on response.
     */
    @Test
    public void testSAMLResponseWithEmptyIssuer() {
        try {
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + SAMLInboundTestConstants
                    .SAML_REDIRECT_WITH_EMPTY_ISSUER, HttpMethod.GET, false);
            //TODO : get proper error response after fixing error handling and then assert
            Assert.assertEquals(urlConnection.getResponseCode(), 500);

        } catch (IOException e) {
            Assert.fail("Error while running testSAMLResponseWithWrongSignature test case", e);
        }
    }

    /**
     * Sending out a request with non existing issuer
     */
    @Test
    public void testSAMLResponseWithWrongIssuer() {
        try {
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + SAMLInboundTestConstants
                    .SAML_REDIRECT_REQUEST_WRONG_ISSUER, HttpMethod.GET, false);
            Assert.assertEquals(500, urlConnection.getResponseCode());

        } catch (IOException e) {
            Assert.fail("Error while running testSAMLResponseWithWrongIssuer test case", e);
        }
    }

    /**
     * Enable assertion encryption and see whether we are getting back an encrypted assertion.
     */
    @Test
    public void testEnableAssertionEncryption() {
        ServiceProviderConfig serviceProviderConfig = SAMLInboundTestUtils.getServiceProviderConfigs
                (SAMLInboundTestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        try {
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doEnableEncryptedAssertion", "true");
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + SAMLInboundTestConstants
                    .SAML_REQUEST, HttpMethod.GET, false);
            String locationHeader = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(SAMLInboundTestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = SAMLInboundTestUtils.request
                    (SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" + SAMLInboundTestConstants.RELAY_STATE + "=" +
                            relayState + "&" + SAMLInboundTestConstants.ASSERTION + "=" +
                            SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            if (cookie != null) {
                cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
                Assert.assertNotNull(cookie);
                String response = SAMLInboundTestUtils.getContent(urlConnection);
                if (response != null) {
                    String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
                    try {
                        Response samlResponseObject = SAMLInboundTestUtils.getSAMLResponse(samlResponse);
                        Assert.assertTrue(samlResponseObject.getAssertions().isEmpty());
                        Assert.assertTrue(samlResponseObject.getEncryptedAssertions().size() > 0);
                    } catch (SAMLServerException e) {
                        Assert.fail("Error while asserting on encrypted assertions test case", e);
                    }
                }
            }
        } catch (IOException e) {
            Assert.fail("Error while asserting on encrypted assertions test case", e);
        } finally {
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doEnableEncryptedAssertion", "false");
        }
    }

    /**
     * Test response signing disabled.
     */
    @Test
    public void testSAMLResponseSigningDisabled() {
        try {
            ServiceProviderConfig serviceProviderConfig = SAMLInboundTestUtils.getServiceProviderConfigs
                    (SAMLInboundTestConstants.SAMPLE_ISSUER_NAME, bundleContext);
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doSignResponse", "false");
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + SAMLInboundTestConstants
                    .SAML_REQUEST, HttpMethod.GET, false);
            String locationHeader = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(SAMLInboundTestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = SAMLInboundTestUtils.request
                    (SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" + SAMLInboundTestConstants.RELAY_STATE + "=" +
                            relayState + "&" + SAMLInboundTestConstants.ASSERTION + "=" +
                            SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            if (cookie != null) {
                cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
                Assert.assertNotNull(cookie);
                String response = SAMLInboundTestUtils.getContent(urlConnection);
                if (response != null) {
                    String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
                    try {
                        Response samlResponseObject = SAMLInboundTestUtils.getSAMLResponse(samlResponse);
                        Assert.assertEquals(SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, samlResponseObject
                                .getAssertions().get(0).getSubject().getNameID().getValue());
                        Assert.assertNull(samlResponseObject.getSignature());
                    } catch (SAMLServerException e) {
                        Assert.fail("Error while building response object", e);
                    }
                }
            }
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case", e);
        }
    }

    /**
     * Test whether we are getting back signature when the signing is enabled.
     */
    @Test
    public void testSAMLResponseSigningEnabled() {
        try {
            ServiceProviderConfig serviceProviderConfig = SAMLInboundTestUtils.getServiceProviderConfigs
                    (SAMLInboundTestConstants.SAMPLE_ISSUER_NAME, bundleContext);
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doSignResponse", "true");
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" +
                            SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + SAMLInboundTestConstants.SAML_REQUEST, HttpMethod.GET,
                    false);
            String locationHeader = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(SAMLInboundTestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = SAMLInboundTestUtils.request
                    (SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" + SAMLInboundTestConstants.RELAY_STATE + "=" + relayState +
                            "&" + SAMLInboundTestConstants.ASSERTION + "=" +
                            SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            if (cookie != null) {
                cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
                Assert.assertNotNull(cookie);
                String response = SAMLInboundTestUtils.getContent(urlConnection);
                if (response != null) {
                    String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
                    try {
                        Response samlResponseObject = SAMLInboundTestUtils.getSAMLResponse(samlResponse);
                        Assert.assertEquals(SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, samlResponseObject
                                .getAssertions().get(0).getSubject().getNameID().getValue());
                        Assert.assertNotNull(samlResponseObject.getSignature());
                    } catch (SAMLServerException e) {
                        Assert.fail("Error while building response object from SAML response string", e);
                    }
                }
            }
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case", e);
        }
    }

    /**
     * Test with assertion signing enabled. Assert on the signature we are getting back in assertion.
     */
    @Test
    public void testSAMLAssertionSigningEnabled() {
        ServiceProviderConfig serviceProviderConfig = SAMLInboundTestUtils.getServiceProviderConfigs
                (SAMLInboundTestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        try {

            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doSignAssertions", "true");
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + SAMLInboundTestConstants
                    .SAML_REQUEST, HttpMethod.GET, false);
            String locationHeader = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(SAMLInboundTestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = SAMLInboundTestUtils.request
                    (SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" + SAMLInboundTestConstants.RELAY_STATE + "=" +
                            relayState + "&" + SAMLInboundTestConstants.ASSERTION + "=" +
                            SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            if (cookie != null) {
                cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
                Assert.assertNotNull(cookie);
                String response = SAMLInboundTestUtils.getContent(urlConnection);
                if (response != null) {
                    String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
                    try {
                        Response samlResponseObject = SAMLInboundTestUtils.getSAMLResponse(samlResponse);
                        Assert.assertEquals(SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, samlResponseObject
                                .getAssertions().get(0).getSubject().getNameID().getValue());
                        Assert.assertNotNull(samlResponseObject.getAssertions().get(0).getSignature());
                    } catch (SAMLServerException e) {
                        Assert.fail("Error while building response object from SAML response string", e);
                    }
                }
            }
        } catch (IOException e) {
            Assert.fail("Error while running testSAMLAssertionSigningEnabled test case", e);
        } finally {
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doSignAssertions", "false");
        }
    }

    /**
     * When the assertion signing is disabled, there shouldn't be a signature component in assertions.
     */
    @Test
    public void testSAMLAssertionSigningDisabled() {
        ServiceProviderConfig serviceProviderConfig = SAMLInboundTestUtils.getServiceProviderConfigs
                (SAMLInboundTestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        try {

            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doSignAssertions", "false");
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + SAMLInboundTestConstants
                    .SAML_REQUEST, HttpMethod.GET, false);
            String locationHeader = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(SAMLInboundTestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = SAMLInboundTestUtils.request
                    (SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" + SAMLInboundTestConstants.RELAY_STATE + "=" +
                            relayState + "&" + SAMLInboundTestConstants.ASSERTION + "=" +
                            SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            if (cookie != null) {
                cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
                Assert.assertNotNull(cookie);
                String response = SAMLInboundTestUtils.getContent(urlConnection);
                if (response != null) {
                    String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
                    try {
                        Response samlResponseObject = SAMLInboundTestUtils.getSAMLResponse(samlResponse);
                        Assert.assertEquals(SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, samlResponseObject
                                .getAssertions().get(0).getSubject().getNameID().getValue());
                        Assert.assertNull(samlResponseObject.getAssertions().get(0).getSignature());
                    } catch (SAMLServerException e) {
                        Assert.fail("Error while building response object from SAML response string", e);
                    }
                }
            }
        } catch (IOException e) {
            Assert.fail("Error while running testSAMLAssertionSigningDisabled test case", e);
        } finally {
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doSignAssertions", "true");
        }
    }

    /**
     * Assert on error response
     * Added this as a unit test since bootstrapping is needed.
     */
    @Test
    public void testHandleException() {
        try {
            DefaultBootstrap.bootstrap();
            String errorResponse = SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse("ErrorStatus", "ErrorMessage",
                    "https://localhost:9292/error");
            Assert.assertNotNull(errorResponse);
        } catch (ConfigurationException e) {
            Assert.fail("Error while bootstrapping opensaml");
        }

    }

    /**
     * SAML request without signature validation turned on.
     */
    @Test
    public void testSAMLAssertionWithoutRequestSignatureValidation() {
        ServiceProviderConfig serviceProviderConfig = SAMLInboundTestUtils.getServiceProviderConfigs
                (SAMLInboundTestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        try {
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doValidateSignatureInRequests", "false");

            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SAML_REQUEST_PARAM + "=" + SAMLInboundTestConstants
                    .SAML_REQUEST, HttpMethod.GET, false);

            String locationHeader = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(SAMLInboundTestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = SAMLInboundTestUtils.request
                    (SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" + SAMLInboundTestConstants.RELAY_STATE + "=" +
                            relayState + "&" + SAMLInboundTestConstants.ASSERTION + "=" +
                            SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            if (cookie != null) {
                cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
                Assert.assertNotNull(cookie);
                String response = SAMLInboundTestUtils.getContent(urlConnection);
                if (response != null) {
                    String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
                    try {
                        Response samlResponseObject = SAMLInboundTestUtils.getSAMLResponse(samlResponse);
                        Assert.assertEquals(SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, samlResponseObject
                                .getAssertions().get(0).getSubject().getNameID().getValue());
                        Assert.assertNull(samlResponseObject.getAssertions().get(0).getSignature());
                    } catch (SAMLServerException e) {
                        log.error("Error while building response object from SAML response string", e);
                    }
                }
            }
        } catch (IOException e) {
            Assert.fail("Error while running testSAMLAssertionWithoutRequestValidation test case");
        } finally {
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doValidateSignatureInRequests", "true");
        }
    }

    /**
     * Test error responses
     */
    @Test
    public void testSAMLResponseBuilderFactory() {
        SAMLSPInitResponseHandler responseHandler = new SAMLSPInitResponseHandler();
        AuthenticationContext authenticationContext = new AuthenticationContext(null);
        SAMLMessageContext samlMessageContext = new SAMLMessageContext(null, null);
        SAMLSPInitRequest.SAMLSpInitRequestBuilder spInitRequestBuilder = new SAMLSPInitRequest
                .SAMLSpInitRequestBuilder();

        SAMLRequest samlRequest = new SAMLSPInitRequest(spInitRequestBuilder);
        samlMessageContext.setIdentityRequest(samlRequest);
        samlMessageContext.setIsPassive(true);
        authenticationContext.addParameter(SAMLSSOConstants.SAMLContext, samlMessageContext);
        authenticationContext.setUniqueId(SAMLInboundTestConstants.SAMPLE_ISSUER_NAME);
        try {
            GatewayHandlerResponse response = responseHandler.buildErrorResponse(authenticationContext, new
                    GatewayException("GatewayException"));
            Assert.assertNotNull(response);
            Assert.assertNotNull(response.getGatewayResponseBuilder());
            SAMLLoginResponse.SAMLLoginResponseBuilder samlLoginResponseBuilder = (SAMLLoginResponse
                    .SAMLLoginResponseBuilder) response
                    .getGatewayResponseBuilder();
            Assert.assertNotNull(samlLoginResponseBuilder.build());
        } catch (ResponseHandlerException e) {
            Assert.fail("Error while building error response", e);
        }
    }
}
