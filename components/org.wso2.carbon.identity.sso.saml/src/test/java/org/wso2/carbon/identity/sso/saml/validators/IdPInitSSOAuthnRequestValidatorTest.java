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

import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.xml.XMLObject;
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

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
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
public class IdPInitSSOAuthnRequestValidatorTest extends PowerMockTestCase{

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @DataProvider(name = "testValidate")
    public static Object[][] testValidateData() {
        String[] noSPEntityID = new String[]{TestConstants.ACS_URL, "true", TestConstants.RETURN_TO_URL, null};
        String[] spEntityIDWithNoTenantDomain = new String[]{TestConstants.ACS_URL, "true",
                TestConstants.RETURN_TO_URL, TestConstants.SP_ENTITY_ID};
        String[] spEntityIDWithTenantDomain = new String[]{TestConstants.ACS_URL, "true",
                TestConstants.RETURN_TO_URL, TestConstants.SP_ENTITY_ID_WITH_TENANT_DOMAIN};

        return new Object[][]{
                {noSPEntityID, false, false},
                {spEntityIDWithNoTenantDomain, false, false},
                {spEntityIDWithTenantDomain, false, false},
                {spEntityIDWithNoTenantDomain, true, true},
                {spEntityIDWithTenantDomain, true, true}
        };
    }

    @Test(dataProvider = "testValidate")
    public void testValidate(String[] queryParams, boolean shouldMakeIsuerExist, boolean isValidRequest)
            throws Exception {

        QueryParamDTO[] queryParamDTOS = new QueryParamDTO[]{
                new QueryParamDTO(SAMLSSOConstants.QueryParameter.ACS.toString(), queryParams[0]),
                new QueryParamDTO(SAMLSSOConstants.QueryParameter.SLO.toString(), queryParams[1]),
                new QueryParamDTO(SAMLSSOConstants.QueryParameter.RETURN_TO.toString(), queryParams[2]),
                new QueryParamDTO(SAMLSSOConstants.QueryParameter.SP_ENTITY_ID.toString(), queryParams[3])
        };

        SAMLSSOUtil.doBootstrap();

        SSOAuthnRequestValidator authnRequestValidator =
                SAMLSSOUtil.getIdPInitSSOAuthnRequestValidator(queryParamDTOS, "relayString");

        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.buildErrorResponse(anyString(), anyString(), anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.marshall(any(XMLObject.class))).thenCallRealMethod();
        when(SAMLSSOUtil.compressResponse(anyString())).thenCallRealMethod();
        when(SAMLSSOUtil.getIssuer()).thenReturn(new IssuerBuilder().buildObject());
        when(SAMLSSOUtil.isSAMLIssuerExists(anyString(), anyString())).thenReturn(shouldMakeIsuerExist);

        SAMLSSOReqValidationResponseDTO samlssoReqValidationResponseDTO = authnRequestValidator.validate();
        if(isValidRequest){
            assertTrue(samlssoReqValidationResponseDTO.isValid(), "Should be a valid SAML request.");
            assertNull(samlssoReqValidationResponseDTO.getResponse(), "Should not contain an error response.");
        } else {
            assertFalse(samlssoReqValidationResponseDTO.isValid(), "Should not be a valid SAML request.");
            assertNotNull(samlssoReqValidationResponseDTO.getResponse(), "Should contain an erro response.");
        }
    }
}
