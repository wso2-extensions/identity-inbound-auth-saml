/*
 * Copyright (c) 2007, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderInfoDTO;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ClientException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;

public class SAMLSSOConfigService extends AbstractAdmin {

    private static final Log log = LogFactory.getLog(SAMLSSOConfigService.class);
    private SAMLSSOConfigServiceImpl samlssoConfigService = new SAMLSSOConfigServiceImpl();

    /**
     * @param spDto
     * @return
     * @throws IdentityException
     */
    public boolean addRPServiceProvider(SAMLSSOServiceProviderDTO spDto) throws IdentityException {

        try {
            return samlssoConfigService.addRPServiceProvider(spDto);
        } catch (IdentityException ex) {
            String message = "Error while creating SAML service provider.";
            throw handleException(ex, message);
        }
    }

    /**
     * @param metadata
     * @return
     * @throws IdentitySAML2SSOException
     */

    public SAMLSSOServiceProviderDTO uploadRPServiceProvider(String metadata) throws IdentitySAML2SSOException {

        try {
            return samlssoConfigService.uploadRPServiceProvider(metadata);
        } catch (IdentitySAML2SSOException ex) {
            String message = "Error while uploading SAML service provider.";
            throw handleException(ex, message);
        }
    }

    private <T extends Exception> T handleException(T ex, String message) {

        if (ex instanceof IdentitySAML2ClientException) {
            if (log.isDebugEnabled()) {
                log.debug(message, ex);
            }
        } else {
            log.error(message, ex);
        }
        return ex;
    }

    /**
     * @return
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderInfoDTO getServiceProviders() throws IdentityException {

        return samlssoConfigService.getServiceProviders();
    }

    /**
     * Returns SAML Service provider information
     *
     * @param issuer unique identifier of SAML the service provider.
     * @return SAMLSSOServiceProviderDTO containing service provider configurations.
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDTO getServiceProvider(String issuer) throws IdentityException {

        return samlssoConfigService.getServiceProvider(issuer);
    }

    /**
     * @return
     * @throws IdentityException
     */
    public String[] getCertAliasOfPrimaryKeyStore() throws IdentityException {

        return samlssoConfigService.getCertAliasOfPrimaryKeyStore();
    }

    public String[] getSigningAlgorithmUris() {

        return samlssoConfigService.getSigningAlgorithmUris();
    }

    public String getSigningAlgorithmUriByConfig() {

        return samlssoConfigService.getSigningAlgorithmUriByConfig();
    }

    public String[] getDigestAlgorithmURIs() {

        return samlssoConfigService.getDigestAlgorithmURIs();
    }

    public String getDigestAlgorithmURIByConfig() {

        return samlssoConfigService.getDigestAlgorithmURIByConfig();
    }

    public String[] getAssertionEncryptionAlgorithmURIs() {

        return samlssoConfigService.getAssertionEncryptionAlgorithmURIs();
    }

    public String getAssertionEncryptionAlgorithmURIByConfig() {

        return samlssoConfigService.getAssertionEncryptionAlgorithmURIByConfig();
    }

    public String[] getKeyEncryptionAlgorithmURIs() {

        return samlssoConfigService.getKeyEncryptionAlgorithmURIs();
    }

    public String getKeyEncryptionAlgorithmURIByConfig() {

        return samlssoConfigService.getKeyEncryptionAlgorithmURIByConfig();
    }

    /**
     * @param issuer
     * @return
     * @throws IdentityException
     */
    public boolean removeServiceProvider(String issuer) throws IdentityException {

        return samlssoConfigService.removeServiceProvider(issuer);
    }

    /**
     * @return
     * @throws IdentityException
     */
    public String[] getClaimURIs() throws IdentityException {

        return samlssoConfigService.getClaimURIs();
    }

}
