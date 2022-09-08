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

package org.wso2.carbon.identity.sso.saml.validators;

import org.mockito.Mock;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.core.xml.XMLObject;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.TestConstants;
import org.wso2.carbon.identity.sso.saml.dto.QueryParamDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

/**
 * Unit test cases for IdPInitSSOAuthnRequestValidatorTest.
 */
@PowerMockIgnore({"javax.net.*"})
@PrepareForTest({SAMLSSOUtil.class})
public class IdPInitSSOAuthnRequestValidatorTest extends PowerMockTestCase {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new PowerMockObjectFactory();
    }

    @Mock
    private RealmService mockRealmService;

    @Mock
    private TenantManager mockTenantManager;

    @DataProvider(name = "testValidate")
    public static Object[][] testValidateData() {

        String[] noSPEntityID = new String[]{TestConstants.ACS_URL, "true", TestConstants.RETURN_TO_URL, null, null};
        String[] spEntityIDWithNoTenantDomainAndNoSPQualifier = new String[]{TestConstants.ACS_URL, "true",
                TestConstants.RETURN_TO_URL, TestConstants.SP_ENTITY_ID, null};
        String[] spEntityIDWithSPQualifierAndNoTenantDomain = new String[]{TestConstants.ACS_URL, "true",
                TestConstants.RETURN_TO_URL, TestConstants.SP_ENTITY_ID, TestConstants.SP_QUALIFIER};
        String[] spEntityIDWithTenantDomainAndNoSPQualifier = new String[]{TestConstants.ACS_URL, "true",
                TestConstants.RETURN_TO_URL, TestConstants.SP_ENTITY_ID_WITH_TENANT_DOMAIN, null};
        String[] spEntityIDWithTenantDomainAndSPQualifier = new String[]{TestConstants.ACS_URL, "true",
                TestConstants.RETURN_TO_URL, TestConstants.SP_ENTITY_ID_WITH_TENANT_DOMAIN, TestConstants.SP_QUALIFIER};

        return new Object[][]{
                {noSPEntityID, false, false},
                {spEntityIDWithNoTenantDomainAndNoSPQualifier, false, false},
                {spEntityIDWithTenantDomainAndNoSPQualifier, false, false},
                {spEntityIDWithSPQualifierAndNoTenantDomain, true, true},
                {spEntityIDWithNoTenantDomainAndNoSPQualifier, true, true},
                {spEntityIDWithTenantDomainAndNoSPQualifier, true, true},
                {spEntityIDWithTenantDomainAndSPQualifier, true, true},
        };
    }

    @Test(dataProvider = "testValidate")
    public void testValidate(String[] queryParams, boolean shouldMakeIssuerExist, boolean isValidRequest)
            throws Exception {

        QueryParamDTO[] queryParamDTOS = new QueryParamDTO[]{
                new QueryParamDTO(SAMLSSOConstants.QueryParameter.ACS.toString(), queryParams[0]),
                new QueryParamDTO(SAMLSSOConstants.QueryParameter.SLO.toString(), queryParams[1]),
                new QueryParamDTO(SAMLSSOConstants.QueryParameter.RETURN_TO.toString(), queryParams[2]),
                new QueryParamDTO(SAMLSSOConstants.QueryParameter.SP_ENTITY_ID.toString(), queryParams[3])
        };

        SAMLSSOUtil.doBootstrap();

        mockStatic(SAMLSSOUtil.class);

        when(SAMLSSOUtil.getRealmService()).thenReturn(mockRealmService);
        when(mockRealmService.getTenantManager()).thenReturn(mockTenantManager);
        when(mockTenantManager.getTenantId(anyString())).thenReturn(4567);

        when(SAMLSSOUtil.getTenantDomainFromThreadLocal()).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(SAMLSSOUtil.resolveIssuerQualifier(any(QueryParamDTO[].class), anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.getIdPInitSSOAuthnRequestValidator(any(QueryParamDTO[].class), anyString()))
                .thenCallRealMethod();

        SSOAuthnRequestValidator authnRequestValidator =
                SAMLSSOUtil.getIdPInitSSOAuthnRequestValidator(queryParamDTOS, "relayString");

        when(SAMLSSOUtil.buildErrorResponse(anyString(), anyString(), isNull())).thenCallRealMethod();
        when(SAMLSSOUtil.marshall(any(XMLObject.class))).thenCallRealMethod();
        when(SAMLSSOUtil.compressResponse(anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.getIssuer()).thenReturn(new IssuerBuilder().buildObject());
        when(SAMLSSOUtil.isSAMLIssuerExists(anyString(), anyString())).thenReturn(shouldMakeIssuerExist);

        SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = authnRequestValidator.validate();
        if (isValidRequest) {
            assertTrue(samlssoReqValidationResponseDTO.isValid(), "Should be a valid SAML request.");
            assertNull(samlssoReqValidationResponseDTO.getResponse(), "Should not contain an error response.");
        } else {
            assertFalse(samlssoReqValidationResponseDTO.isValid(), "Should not be a valid SAML request.");
            assertNotNull(samlssoReqValidationResponseDTO.getResponse(), "Should contain an error response.");
        }
    }
}
