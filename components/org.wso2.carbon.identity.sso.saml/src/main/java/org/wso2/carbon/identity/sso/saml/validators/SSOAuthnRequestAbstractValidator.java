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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

/**
 * SSOAuthnRequestAbstractValidator is comprised of the implementation of splitAppendedTenantDomain().
 */
public abstract class SSOAuthnRequestAbstractValidator implements SSOAuthnRequestValidator {

    private static Log log = LogFactory.getLog(SSOAuthnRequestAbstractValidator.class);

    protected String splitAppendedTenantDomain(String issuer) throws UserStoreException, IdentityException {

        if (IdentityUtil.isBlank(SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
            if (issuer.contains("@")) {
                String tenantDomain = issuer.substring(issuer.lastIndexOf('@') + 1);
                issuer = issuer.substring(0, issuer.lastIndexOf('@'));
                if (StringUtils.isNotBlank(tenantDomain) && StringUtils.isNotBlank(issuer)) {
                    SAMLSSOUtil.setTenantDomainInThreadLocal(tenantDomain);
                    if (log.isDebugEnabled()) {
                        log.debug("Tenant Domain: " + tenantDomain + " & Issuer name: " + issuer + " has been split.");
                    }
                }
            }
        }

        if (IdentityUtil.isBlank(SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
            SAMLSSOUtil.setTenantDomainInThreadLocal(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            if (log.isDebugEnabled()) {
                log.debug("Thread local tenant domain is set to: " + MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            }
        }
        return issuer;
    }
}
