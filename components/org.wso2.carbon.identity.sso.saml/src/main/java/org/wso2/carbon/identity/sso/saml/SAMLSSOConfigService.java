/*
 * Copyright (c) (2007-2023), WSO2 LLC. (https://www.wso2.com).
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
    private SAMLSSOConfigServiceImpl samlSSOConfigServiceImpl = new SAMLSSOConfigServiceImpl();

    /**
     * @param spDto
     * @return
     * @throws IdentityException
     */
    public boolean addRPServiceProvider(SAMLSSOServiceProviderDTO spDto) throws IdentityException {

        try {
            return samlSSOConfigServiceImpl.addRPServiceProvider(spDto);
        } catch (IdentityException ex) {
            throw handleException(ex);
        }
    }

    /**
     * Updates SAML Service provider information.
     *
     * @param serviceProviderDTO    SAMLSSOServiceProviderDTO containing service provider configurations.
     * @param currentIssuer         Issuer of the service provider before the update.
     * @return True if the service provider is updated successfully.
     * @throws IdentityException If an error occurs while updating the service provider.
     */
    public boolean updateRPServiceProvider(SAMLSSOServiceProviderDTO serviceProviderDTO, String currentIssuer)
            throws IdentityException {

        try {
            return samlSSOConfigServiceImpl.updateRPServiceProvider(serviceProviderDTO, currentIssuer);
        } catch (IdentityException ex) {
            throw handleException(ex);
        }
    }

    /**
     * @param metadata
     * @return
     * @throws IdentitySAML2SSOException
     */

    public SAMLSSOServiceProviderDTO uploadRPServiceProvider(String metadata) throws IdentitySAML2SSOException {

        try {
            return samlSSOConfigServiceImpl.uploadRPServiceProvider(metadata);
        } catch (IdentitySAML2SSOException ex) {
            throw handleException(ex);
        }
    }

    /**
     * @return
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderInfoDTO getServiceProviders() throws IdentityException {

        try {
            return samlSSOConfigServiceImpl.getServiceProviders();
        } catch (IdentityException ex) {
            throw handleException(ex);
        }
    }

    /**
     * Returns SAML Service provider information
     *
     * @param issuer unique identifier of SAML the service provider.
     * @return SAMLSSOServiceProviderDTO containing service provider configurations.
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDTO getServiceProvider(String issuer) throws IdentityException {

        try {
            return samlSSOConfigServiceImpl.getServiceProvider(issuer);
        } catch (IdentityException ex) {
            throw handleException(ex);
        }
    }

    /**
     * @return
     * @throws IdentityException
     */
    public String[] getCertAliasOfPrimaryKeyStore() throws IdentityException {

        try {
            return samlSSOConfigServiceImpl.getCertAliasOfPrimaryKeyStore();
        } catch (IdentityException ex) {
            throw handleException(ex);
        }
    }

    public String[] getSigningAlgorithmUris() {

        return samlSSOConfigServiceImpl.getSigningAlgorithmUris();
    }

    public String getSigningAlgorithmUriByConfig() {

        return samlSSOConfigServiceImpl.getSigningAlgorithmUriByConfig();
    }

    public String[] getDigestAlgorithmURIs() {

        return samlSSOConfigServiceImpl.getDigestAlgorithmURIs();
    }

    public String getDigestAlgorithmURIByConfig() {

        return samlSSOConfigServiceImpl.getDigestAlgorithmURIByConfig();
    }

    public String[] getAssertionEncryptionAlgorithmURIs() {

        return samlSSOConfigServiceImpl.getAssertionEncryptionAlgorithmURIs();
    }

    public String getAssertionEncryptionAlgorithmURIByConfig() {

        return samlSSOConfigServiceImpl.getAssertionEncryptionAlgorithmURIByConfig();
    }

    public String[] getKeyEncryptionAlgorithmURIs() {

        return samlSSOConfigServiceImpl.getKeyEncryptionAlgorithmURIs();
    }

    public String getKeyEncryptionAlgorithmURIByConfig() {

        return samlSSOConfigServiceImpl.getKeyEncryptionAlgorithmURIByConfig();
    }

    /**
     * @param issuer
     * @return
     * @throws IdentityException
     */
    public boolean removeServiceProvider(String issuer) throws IdentityException {

        try {
            return samlSSOConfigServiceImpl.removeServiceProvider(issuer);
        } catch (IdentityException ex) {
            throw handleException(ex);
        }
    }

    /**
     * @return
     * @throws IdentityException
     */
    public String[] getClaimURIs() throws IdentityException {

        try {
            return samlSSOConfigServiceImpl.getClaimURIs();
        } catch (IdentityException ex) {
            throw handleException(ex);
        }
    }

    private <T extends Exception> T handleException(T ex) {

        if (ex instanceof IdentitySAML2ClientException) {
            if (log.isDebugEnabled()) {
                log.debug(ex);
            }
        } else {
            log.error(ex);
        }
        return ex;
    }
}
