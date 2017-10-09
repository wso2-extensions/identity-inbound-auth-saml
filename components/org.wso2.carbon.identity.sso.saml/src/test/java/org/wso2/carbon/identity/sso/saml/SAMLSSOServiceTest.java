/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.sso.saml;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.dto.QueryParamDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSORespDTO;
import org.wso2.carbon.identity.sso.saml.processors.IdPInitLogoutRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.IdPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.saml.processors.SPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.*;
import static org.testng.Assert.*;

/**
 * Unit Tests for SAMLSSOService.
 */
@PrepareForTest({IdentityUtil.class, SAMLSSOUtil.class, SAMLSSOReqValidationResponseDTO.class,
    SSOSessionPersistenceManager.class})
public class SAMLSSOServiceTest extends PowerMockTestCase {

    @DataProvider(name = "testAuthenticate")
    public static Object[][] isIDPInitSSOEnabled() {
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

    @Test
    public void testValidateIdPInitSSORequestAuthentication() throws Exception {

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
        when(SAMLSSOUtil.getIdPInitSSOAuthnRequestValidator(any(QueryParamDTO[].class), anyString()))
                .thenCallRealMethod();
        when(SAMLSSOUtil.isSAMLIssuerExists(anyString(), anyString())).thenReturn(true);

        SAMLSSOService samlssoService = new SAMLSSOService();
        SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = samlssoService.validateIdPInitSSORequest(
                relayState, queryString, queryParamDTOs, serverURL, sessionId, rpSessionId, authnMode, isLogout);
        assertTrue(samlssoReqValidationResponseDTO.isValid(), "Should be a valid SAML authentication request.");
        assertTrue(samlssoReqValidationResponseDTO.isIdPInitSSO(), "Should be an IDP initiated SAML SSO request.");
        assertEquals(samlssoReqValidationResponseDTO.getQueryString(), queryString, "Query String should be same as " +
                "the given input query string.");
        assertEquals(samlssoReqValidationResponseDTO.getRpSessionId(), rpSessionId, "RP sessionId should be same as " +
                "the given input RpSessionId.");
    }

    @Test
    public void testValidateIdPInitSSORequestLogout() throws Exception {

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
        when(idPInitLogoutRequestProcessor.process(anyString(), any(QueryParamDTO[].class), anyString()))
                .thenReturn(this.mockValidIDPInitLogoutRequestProcessing(queryParamDTOs));
        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.getIdPInitLogoutRequestProcessor()).thenReturn(idPInitLogoutRequestProcessor);

        SAMLSSOService samlssoService = new SAMLSSOService();
        SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = samlssoService.validateIdPInitSSORequest(
                relayState, queryString, queryParamDTOs, serverURL, sessionId, rpSessionId, authnMode, isLogout);
        assertTrue(samlssoReqValidationResponseDTO.isValid(), "Should be a valid SAML SLO request.");
        assertTrue(samlssoReqValidationResponseDTO.isIdPInitSLO(), "Should be an IDP initiated SLO request");
        assertEquals(samlssoReqValidationResponseDTO.getQueryString(), queryString, "Query String should be same as " +
                "the given input query string.");
        assertEquals(samlssoReqValidationResponseDTO.getRpSessionId(), rpSessionId, "RP sessionId should be same as " +
                "the given input RpSessionId.");
    }

    private SAMLSSOReqValidationResponseDTO mockValidIDPInitLogoutRequestProcessing(QueryParamDTO[] queryParamDTOS) {

        SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = new SAMLSSOReqValidationResponseDTO();
        samlssoReqValidationResponseDTO.setLogOutReq(true);
        samlssoReqValidationResponseDTO.setReturnToURL(queryParamDTOS[2].getValue());
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
        when(ssoSessionPersistenceManager.getSessionIndexFromTokenId(anyString())).thenReturn("theSessionIndex");

        SAMLSSOService samlssoService = new SAMLSSOService();
        assertTrue(samlssoService.doSingleLogout("aSeesionID").isLogOutReq(), " Should return" +
                "SAMLSSOReqValidationResponseDTO where isLogOutReq is true");
    }

}