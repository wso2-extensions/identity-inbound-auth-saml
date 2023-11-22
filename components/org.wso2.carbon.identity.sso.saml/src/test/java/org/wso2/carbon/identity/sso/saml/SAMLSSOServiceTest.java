/*
 * Copyright (c) 2017, WSO2 LLC. (http://www.wso2.org).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.sso.saml;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.dto.QueryParamDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSORespDTO;
import org.wso2.carbon.identity.sso.saml.processors.SPInitLogoutRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.IdPInitLogoutRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.IdPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.SPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertNotNull;

/**
 * Unit Tests for SAMLSSOService.
 */
@PrepareForTest({IdentityUtil.class, SAMLSSOUtil.class, SAMLSSOReqValidationResponseDTO.class,
    SSOSessionPersistenceManager.class, LoggerUtils.class})
public class SAMLSSOServiceTest extends PowerMockTestCase {

    @DataProvider(name = "testAuthenticate")
    public static Object[][] isIDPInitSSOEnabled() {
        return new Object[][]{{true}, {false}};
    }

    @DataProvider(name = "testValidateSPInitSSORequestLogout")
    public static Object[][] logoutRequests() {
        return new Object[][]{
                {TestConstants.ENCODED_POST_LOGOUT_REQUEST, null, true},
                {TestConstants.ENCODED_REDIRECT_LOGOUT_REQUEST,
                        TestConstants.ENCODED_QUERY_STRING_FOR_REDIRECT_LOGOUT_REQUEST,false}
        };
    }

    @DataProvider(name = "testValidateSPInitSSORequestAuthentication")
    public static Object[][] authnRequests() {
        return new Object[][]{
                {TestConstants.ENCODED_POST_AUTHN_REQUEST, null, true},
                {TestConstants.ENCODED_REDIRECT_AUTHN_REQUEST,
                        TestConstants.ENCODED_QUERY_STRING_FOR_AUTHN_REQUEST, false}
        };
    }

    @DataProvider(name = "testValidateIdPInitSSORequestAuthentication")
    public static Object[][] idpInitAuthRequests() {
        return new Object[][]{{true}, {false}};
    }

    @DataProvider(name = "testValidateIdPInitSSORequestLogout")
    public static Object[][] idpInitLogoutRequests() {
        return new Object[][]{{true}, {false}};
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @Test
    public void testIsOpenIDLoginAccepted() throws Exception {

        assertFalse(SAMLSSOService.isOpenIDLoginAccepted(), "If there is no \"SSOService.AcceptOpenIDLogin\" config  " +
                "property is set should give false.");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(IdentityConstants.ServerConfig.ACCEPT_OPENID_LOGIN)).thenReturn(" true ");
        assertTrue(SAMLSSOService.isOpenIDLoginAccepted(), "If the property is String true (with spaces) should give" +
                " boolean true.");
    }

    @Test
    public void testIsSAMLSSOLoginAccepted() throws Exception {

        assertFalse(SAMLSSOService.isSAMLSSOLoginAccepted(), "If there is no \"OpenID.AcceptSAMLSSOLogin\" config  " +
                "property is set should give false.");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(IdentityConstants.ServerConfig.ACCEPT_SAMLSSO_LOGIN)).thenReturn(" true ");
        assertTrue(SAMLSSOService.isSAMLSSOLoginAccepted(), "If the property is String true (with spaces) should give" +
                " boolean true.");
    }

    @Test(dataProvider = "testValidateSPInitSSORequestAuthentication")
    public void testValidateSPInitSSORequestAuthentication(String encodedAuthnRequest, String queryString,
                                                           boolean isPost) throws Exception {

        SAMLSSOUtil.doBootstrap();
        SAMLSSOServiceProviderDO mockserviceProviderConfigs = new SAMLSSOServiceProviderDO();
        mockserviceProviderConfigs.setIssuer(TestConstants.SP_ENTITY_ID);
        mockserviceProviderConfigs.setAssertionConsumerUrl(TestConstants.ACS_URL);
        mockserviceProviderConfigs.setDoValidateSignatureInRequests(false);
        mockserviceProviderConfigs.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        List<String> acsUrls = new ArrayList<>();
        acsUrls.add(TestConstants.ACS_URL);
        acsUrls.add(TestConstants.RETURN_TO_URL);
        mockserviceProviderConfigs.setAssertionConsumerUrls(acsUrls);
        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.getTenantDomainFromThreadLocal()).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(SAMLSSOUtil.getSPInitSSOAuthnRequestValidator(any(AuthnRequest.class), eq(queryString))).thenCallRealMethod();
        when(SAMLSSOUtil.unmarshall(anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.decodeForPost(anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.decode(anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.isSAMLIssuerExists(anyString(), anyString())).thenReturn(true);
        when(SAMLSSOUtil.getServiceProviderConfig(anyString(), anyString())).thenReturn(mockserviceProviderConfigs);

        SAMLSSOService samlssoService = new SAMLSSOService();
        SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = samlssoService.validateSPInitSSORequest(
                encodedAuthnRequest, queryString, null, null, TestConstants.BASIC_AUTHN_MODE, isPost,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertTrue(samlssoReqValidationResponseDTO.isValid(), "Should be a valid SAML authentication request.");
        assertFalse(samlssoReqValidationResponseDTO.isIdPInitSSO(), "Should not be an IDP initiated SAML SSO request.");
        assertEquals(samlssoReqValidationResponseDTO.getQueryString(), queryString, "Query String should be same as " +
                "the given input query string.");
        assertNull(samlssoReqValidationResponseDTO.getRpSessionId(), "RP sessionId should be same as the given input" +
                " RpSessionId which is null.");
    }

    @Test(dataProvider = "testValidateSPInitSSORequestLogout")
    public void testValidateSPInitSSORequestLogout(String encodedLogoutRequest, String queryString, boolean isPost)
            throws Exception {

        SAMLSSOUtil.doBootstrap();

        SPInitLogoutRequestProcessor spInitLogoutRequestProcessor = mock(SPInitLogoutRequestProcessor.class);
        when(spInitLogoutRequestProcessor.process(any(LogoutRequest.class), anyString(), eq(queryString),
                anyString())).thenReturn(mockValidSPInitLogoutRequestProcessing(TestConstants.ACS_URL));
        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.getTenantDomainFromThreadLocal()).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(SAMLSSOUtil.getSPInitLogoutRequestProcessor()).thenReturn(spInitLogoutRequestProcessor);
        when(SAMLSSOUtil.unmarshall(anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.decodeForPost(anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.decode(anyString())).thenCallRealMethod();

        SAMLSSOService samlssoService = new SAMLSSOService();
        SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = samlssoService.validateSPInitSSORequest(
                encodedLogoutRequest, queryString, "sessionId", null, TestConstants.BASIC_AUTHN_MODE,
                isPost, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertNotNull(samlssoReqValidationResponseDTO, "Validation response of SP-init SLO request should not be " +
                "null.");
    }

    private SAMLSSOReqValidationResponseDTO mockValidSPInitLogoutRequestProcessing(String ACSUrl) {

        SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = new SAMLSSOReqValidationResponseDTO();
        samlssoReqValidationResponseDTO.setLogOutReq(true);
        samlssoReqValidationResponseDTO.setAssertionConsumerURL(ACSUrl);
        samlssoReqValidationResponseDTO.setValid(true);
        return samlssoReqValidationResponseDTO;
    }

    @Test(dataProvider = "testValidateIdPInitSSORequestAuthentication")
    public void testValidateIdPInitSSORequestAuthentication(boolean isPassive) throws Exception {

        // Inputs for SAMLSSOService's validateIdPInitSSORequest method.
        String relayState = null;
        String queryString = "spEntityID=travelocity.com";
        QueryParamDTO[] queryParamDTOs = {
                new QueryParamDTO("acs", null),
                new QueryParamDTO("slo", null),
                new QueryParamDTO("returnTo", null),
                new QueryParamDTO("spEntityID", "travelocity.com")
        };
        String serverURL = "https://localhost:9443/authenticationendpoint/samlsso_logout.do";
        String sessionId = null;
        String rpSessionId = null;
        String authnMode = "usernamePasswordBasedAuthn";
        boolean isLogout = false;

        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.getTenantDomainFromThreadLocal()).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(SAMLSSOUtil.resolveIssuerQualifier(any(QueryParamDTO[].class), anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.getIdPInitSSOAuthnRequestValidator(any(QueryParamDTO[].class), eq(relayState)))
                .thenCallRealMethod();
        when(SAMLSSOUtil.isSAMLIssuerExists(anyString(), anyString())).thenReturn(true);

        SAMLSSOService samlssoService = new SAMLSSOService();
        SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = samlssoService.validateIdPInitSSORequest(
                relayState, queryString, queryParamDTOs, serverURL, sessionId, rpSessionId, authnMode, isLogout,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME,isPassive);
        assertTrue(samlssoReqValidationResponseDTO.isValid(), "Should be a valid SAML authentication request.");
        assertTrue(samlssoReqValidationResponseDTO.isIdPInitSSO(), "Should be an IDP initiated SAML SSO request.");
        assertEquals(samlssoReqValidationResponseDTO.getQueryString(), queryString, "Query String should be same as " +
                "the given input query string.");
        assertEquals(samlssoReqValidationResponseDTO.getRpSessionId(), rpSessionId, "RP sessionId should be same as " +
                "the given input RpSessionId.");
    }

    @Test(dataProvider = "testValidateIdPInitSSORequestLogout")
    public void testValidateIdPInitSSORequestLogout(boolean isPassive) throws Exception {

        // Inputs for SAMLSSOService's validateIdPInitSSORequest method.
        String relayState = null;
        String queryString = "true&spEntityID=travelocity.com&returnTo=http://localhost.com:8080/travelocity.com/";
        QueryParamDTO[] queryParamDTOs = {
                new QueryParamDTO("acs", null),
                new QueryParamDTO("slo", "true"),
                new QueryParamDTO("returnTo", "http://localhost.com:8080/travelocity.com/index.jsp"),
                new QueryParamDTO("spEntityID", "travelocity.com")
        };
        String serverURL = "https://localhost:9443/authenticationendpoint/samlsso_logout.do";
        String sessionId = "39d43ee3-9896-4d37-8b0d-86abe2047cd1";
        String rpSessionId = null;
        String authnMode = "usernamePasswordBasedAuthn";
        boolean isLogout = true;

        IdPInitLogoutRequestProcessor idPInitLogoutRequestProcessor = mock(IdPInitLogoutRequestProcessor.class);
        when(idPInitLogoutRequestProcessor.process(anyString(), any(QueryParamDTO[].class), anyString(), anyString()))
                .thenReturn(mockValidIDPInitLogoutRequestProcessing(queryParamDTOs[2].getValue()));
        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.getIdPInitLogoutRequestProcessor()).thenReturn(idPInitLogoutRequestProcessor);

        SAMLSSOService samlssoService = new SAMLSSOService();
        SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = samlssoService.validateIdPInitSSORequest(
                relayState, queryString, queryParamDTOs, serverURL, sessionId, rpSessionId, authnMode, isLogout,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, isPassive);
        assertTrue(samlssoReqValidationResponseDTO.isValid(), "Should be a valid SAML SLO request.");
        assertTrue(samlssoReqValidationResponseDTO.isIdPInitSLO(), "Should be an IDP initiated SLO request");
        assertEquals(samlssoReqValidationResponseDTO.getQueryString(), queryString, "Query String should be same as " +
                "the given input query string.");
        assertEquals(samlssoReqValidationResponseDTO.getRpSessionId(), rpSessionId, "RP sessionId should be same as " +
                "the given input RpSessionId.");
    }

    private SAMLSSOReqValidationResponseDTO mockValidIDPInitLogoutRequestProcessing(String returnToUrl) {

        SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = new SAMLSSOReqValidationResponseDTO();
        samlssoReqValidationResponseDTO.setLogOutReq(true);
        samlssoReqValidationResponseDTO.setReturnToURL(returnToUrl);
        samlssoReqValidationResponseDTO.setValid(true);
        return samlssoReqValidationResponseDTO;
    }

    @Test(dataProvider = "testAuthenticate")
    public void testAuthenticate(boolean isIDPInitSSOEnabled) throws Exception {

        SAMLSSOAuthnReqDTO authReqDTO = mock(SAMLSSOAuthnReqDTO.class);
        when(authReqDTO.isIdPInitSSOEnabled()).thenReturn(isIDPInitSSOEnabled);

        if (isIDPInitSSOEnabled) {
            IdPInitSSOAuthnRequestProcessor authnRequestProcessor = mock(IdPInitSSOAuthnRequestProcessor.class);
            mockStatic(SAMLSSOUtil.class);
            when(SAMLSSOUtil.getIdPInitSSOAuthnRequestProcessor()).thenReturn(authnRequestProcessor);
            when(authnRequestProcessor.process(any(SAMLSSOAuthnReqDTO.class), anyString(), anyBoolean(), anyString(),
                    anyString())).thenReturn(new SAMLSSORespDTO());

            assertTrue(executeAuthenticate(authReqDTO) instanceof SAMLSSORespDTO, "Should go through " +
                    "IdPInitSSOAuthnRequestProcessor's process method.");
        } else {
            SPInitSSOAuthnRequestProcessor authnRequestProcessor = mock(SPInitSSOAuthnRequestProcessor.class);
            mockStatic(SAMLSSOUtil.class);
            when(SAMLSSOUtil.getSPInitSSOAuthnRequestProcessor()).thenReturn(authnRequestProcessor);
            when(authnRequestProcessor.process(any(SAMLSSOAuthnReqDTO.class), anyString(), anyBoolean(), anyString(),
                    anyString())).thenReturn(new SAMLSSORespDTO());

            assertTrue(executeAuthenticate(authReqDTO) instanceof SAMLSSORespDTO, "Should go through " +
                    "SPInitSSOAuthnRequestProcessor's process method.");
        }
    }

    @Test(dataProvider = "testAuthenticate", expectedExceptions = IdentityException.class)
    public void testAuthenticateException(boolean isIDPInitSSOEnabled) throws Exception {

        SAMLSSOAuthnReqDTO authReqDTO = mock(SAMLSSOAuthnReqDTO.class);
        when(authReqDTO.isIdPInitSSOEnabled()).thenReturn(isIDPInitSSOEnabled);

        if (isIDPInitSSOEnabled) {
            IdPInitSSOAuthnRequestProcessor authnRequestProcessor = mock(IdPInitSSOAuthnRequestProcessor.class);
            mockStatic(SAMLSSOUtil.class);
            when(SAMLSSOUtil.getIdPInitSSOAuthnRequestProcessor()).thenReturn(authnRequestProcessor);
            when(authnRequestProcessor.process(any(SAMLSSOAuthnReqDTO.class), anyString(), anyBoolean(), anyString(),
                    anyString())).thenThrow(IdentityException.class);

            executeAuthenticate(authReqDTO);
        } else {
            SPInitSSOAuthnRequestProcessor authnRequestProcessor = mock(SPInitSSOAuthnRequestProcessor.class);
            mockStatic(SAMLSSOUtil.class);
            when(SAMLSSOUtil.getSPInitSSOAuthnRequestProcessor()).thenReturn(authnRequestProcessor);
            when(authnRequestProcessor.process(any(SAMLSSOAuthnReqDTO.class), anyString(), anyBoolean(), anyString(),
                    anyString())).thenThrow(IdentityException.class);

            executeAuthenticate(authReqDTO);
        }
    }

    private SAMLSSORespDTO executeAuthenticate(SAMLSSOAuthnReqDTO authReqDTO) throws IdentityException {
        SAMLSSOService samlssoService = new SAMLSSOService();
        return samlssoService.authenticate(authReqDTO, "1234", true, "fb", "basic");
    }

    @Test
    public void testDoSingleLogout() throws Exception {

        SSOSessionPersistenceManager ssoSessionPersistenceManager = mock(SSOSessionPersistenceManager.class);
        mockStatic(SSOSessionPersistenceManager.class);
        when(SSOSessionPersistenceManager.getPersistenceManager()).thenReturn(ssoSessionPersistenceManager);
        when(ssoSessionPersistenceManager.getSessionIndexFromTokenId(anyString(), anyString())).thenReturn("theSessionIndex");
        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);

        SAMLSSOService samlssoService = new SAMLSSOService();
        assertTrue(samlssoService.doSingleLogout("aSeesionID").isLogOutReq(), " Should return" +
                "SAMLSSOReqValidationResponseDTO where isLogOutReq is true");
    }

}
