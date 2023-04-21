package org.wso2.carbon.identity.sso.saml;

import org.wso2.carbon.identity.xds.common.constant.XDSOperationType;

public enum SAMLXDSOperationType implements XDSOperationType {

    ADD_RP_SERVICE_PROVIDER,
    CREATE_SERVICE_PROVIDER,
    UPLOAD_RP_SERVICE_PROVIDER,
    CREATE_SERVICE_PROVIDER_WITH_METADATA_URL,
    REMOVE_SERVICE_PROVIDER
}
