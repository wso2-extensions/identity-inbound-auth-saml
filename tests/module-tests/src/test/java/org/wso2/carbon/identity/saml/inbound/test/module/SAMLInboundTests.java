package org.wso2.carbon.identity.saml.inbound.test.module;

import com.google.common.net.HttpHeaders;
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
import org.wso2.carbon.identity.gateway.common.model.sp.ServiceProviderConfig;
import org.wso2.carbon.identity.gateway.common.util.Constants;
import org.wso2.carbon.identity.gateway.store.ServiceProviderConfigStore;
import org.wso2.carbon.identity.saml.exception.SAMLServerException;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;

import javax.inject.Inject;
import javax.ws.rs.HttpMethod;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.file.Paths;
import java.util.List;

/**
 * Tests the TestService.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class SAMLInboundTests {

    private static final Logger log = LoggerFactory.getLogger(SAMLInboundTests.class);

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

    @Test
    public void testSAMLInboundAuthentication() {
        try {
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
            cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
        } catch (IOException e) {
            log.error("Error while running federated authentication test case", e);
        }
    }

    @Test
    public void testSAMLResponse() {
        try {
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
                    } catch (SAMLServerException e) {
                        e.printStackTrace();
                    }
                }
            }
        } catch (IOException e) {
            log.error("Error while running federated authentication test case", e);
        }
    }

    @Test
    public void testSAMLResponseSigningDisabled() {
        try {
            ServiceProviderConfig serviceProviderConfig = getServiceProviderConfigs(SAMLInboundTestConstants
                    .SAMPLE_ISSUER_NAME);
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doSignResponse", "false");
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
                        Assert.assertNull(samlResponseObject.getSignature());
                    } catch (SAMLServerException e) {
                        e.printStackTrace();
                    }
                }
            }
        } catch (IOException e) {
            log.error("Error while running federated authentication test case", e);
        }
    }

    @Test
    public void testSAMLResponseSigningEnabled() {
        try {
            ServiceProviderConfig serviceProviderConfig = getServiceProviderConfigs(SAMLInboundTestConstants
                    .SAMPLE_ISSUER_NAME);
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
                        log.error("Error while building response object from SAML response string", e);
                    }
                }
            }
        } catch (IOException e) {
            log.error("Error while running federated authentication test case", e);
        }
    }


    @Test
    public void testSAMLAssertionSigningEnabled() {
        try {
            ServiceProviderConfig serviceProviderConfig = getServiceProviderConfigs(SAMLInboundTestConstants
                    .SAMPLE_ISSUER_NAME);
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doSignAssertions", "true");
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
                        Assert.assertNotNull(samlResponseObject.getAssertions().get(0).getSignature());
                    } catch (SAMLServerException e) {
                        log.error("Error while building response object from SAML response string", e);
                    }
                }
            }
        } catch (IOException e) {
            log.error("Error while running federated authentication test case", e);
        }
    }


    @Test
    public void testSAMLAssertionSigningDisabled() {
        try {
            ServiceProviderConfig serviceProviderConfig = getServiceProviderConfigs(SAMLInboundTestConstants
                    .SAMPLE_ISSUER_NAME);
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .setProperty("doSignAssertions", "false");
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
                        Assert.assertNull(samlResponseObject.getAssertions().get(0).getSignature());
                    } catch (SAMLServerException e) {
                        log.error("Error while building response object from SAML response string", e);
                    }
                }
            }
        } catch (IOException e) {
            log.error("Error while running federated authentication test case", e);
        }
    }


    private ServiceProviderConfig getServiceProviderConfigs(String uniqueId) {
        ServiceProviderConfigStore serviceProviderConfigStore = this.bundleContext.getService(bundleContext
                .getServiceReference(ServiceProviderConfigStore.class));
        return serviceProviderConfigStore.getServiceProvider(uniqueId);
    }
}
