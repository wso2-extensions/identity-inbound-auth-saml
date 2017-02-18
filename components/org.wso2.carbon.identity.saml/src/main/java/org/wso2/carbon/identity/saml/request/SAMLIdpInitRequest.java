/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.saml.request;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.saml.SAMLSSOConstants;
import org.wso2.msf4j.Request;

public class SAMLIdpInitRequest extends SAMLIdentityRequest {
    public SAMLIdpInitRequest(SAMLIdpInitRequestBuilder builder) {
        super(builder);
    }

    public String getSpEntityID() {
        return (String) this.getParameter(SAMLSSOConstants.QueryParameter.SP_ENTITY_ID.toString());
    }

    public String getSLO() {
        return (String) this.getParameter(SAMLSSOConstants.QueryParameter.SLO.toString());
    }

    public String getAcs() {
        return (String) this.getParameter(SAMLSSOConstants.QueryParameter.ACS.toString());
    }

    public String getReturnTo() {
        return (String) this.getParameter(SAMLSSOConstants.QueryParameter.RETURN_TO.toString());
    }

    public boolean isLogout() {
        return StringUtils.isNotBlank(getSLO()) && StringUtils.equals(getSLO(), "true");
    }

    public static class SAMLIdpInitRequestBuilder extends SAMLIdentityRequestBuilder {
        public SAMLIdpInitRequestBuilder(Request request) {
            super(request);
        }

        public SAMLIdpInitRequestBuilder() {
        }
        @Override
        public SAMLIdpInitRequest build() {
            return new SAMLIdpInitRequest(this);
        }


    }
}
