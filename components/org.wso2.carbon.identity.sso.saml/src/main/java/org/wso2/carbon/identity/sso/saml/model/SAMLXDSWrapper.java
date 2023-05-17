package org.wso2.carbon.identity.sso.saml.model;

import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.xds.common.constant.XDSWrapper;

public class SAMLXDSWrapper implements XDSWrapper {
    private String metadata;
    private String metadataUrl;
    private SAMLSSOServiceProviderDTO ssoServiceProviderDTO;
    private String issuer;
    private String timestamp;

    public SAMLXDSWrapper(SAMLXDSWrapperBuilder builder) {
        this.metadata = builder.metadata;
        this.metadataUrl = builder.metadataUrl;
        this.ssoServiceProviderDTO = builder.ssoServiceProviderDTO;
        this.issuer = builder.issuer;
        this.timestamp = builder.timestamp;
    }

    public String getMetadata() {
        return this.metadata;
    }

    public String getMetadataUrl() {
        return this.metadataUrl;
    }

    public SAMLSSOServiceProviderDTO getSsoServiceProviderDTO() {
        return this.ssoServiceProviderDTO;
    }

    public String getIssuer() {
        return this.issuer;
    }

    public static class SAMLXDSWrapperBuilder {
        private String metadata;
        private String metadataUrl;
        private SAMLSSOServiceProviderDTO ssoServiceProviderDTO;
        private String issuer;
        private String timestamp;

        public SAMLXDSWrapperBuilder() {
        }

        public SAMLXDSWrapperBuilder setMetadata(String metadata) {
            this.metadata = metadata;
            return this;
        }

        public SAMLXDSWrapperBuilder setMetadataUrl(String metadataUrl) {
            this.metadataUrl = metadataUrl;
            return this;
        }

        public SAMLXDSWrapperBuilder setSsoServiceProviderDTO(SAMLSSOServiceProviderDTO ssoServiceProviderDTO) {
            this.ssoServiceProviderDTO = ssoServiceProviderDTO;
            return this;
        }

        public SAMLXDSWrapperBuilder setIssuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public SAMLXDSWrapper build() {

            this.timestamp = String.valueOf(System.currentTimeMillis());
            return new SAMLXDSWrapper(this);
        }
    }
}
