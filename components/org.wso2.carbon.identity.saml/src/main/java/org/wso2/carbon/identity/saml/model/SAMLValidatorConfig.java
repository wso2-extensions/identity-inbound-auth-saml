package org.wso2.carbon.identity.saml.model;

import org.wso2.carbon.identity.gateway.common.model.sp.RequestValidatorConfig;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class SAMLValidatorConfig implements Serializable {

    private static final long serialVersionUID = 1926448600042806841L;
    private RequestValidatorConfig requestValidatorConfig;

    public SAMLValidatorConfig(RequestValidatorConfig requestValidatorConfig) {
        this.requestValidatorConfig = requestValidatorConfig;
    }

    public List<String> getAssertionConsumerUrlList() {
        List assertionConsumerUrls = (List) this.requestValidatorConfig.getProperties().get("assertionConsumerUrls");
        List<String> assertionConsumerUrlStrings = new ArrayList<>();
        assertionConsumerUrls.stream().forEach(a -> assertionConsumerUrlStrings.add((String) a));
        return assertionConsumerUrlStrings;
    }

    public String getAttributeConsumingServiceIndex() {
        return (String) this.requestValidatorConfig.getProperties().get("attributeConsumingServiceIndex");
    }

    public String getCertAlias() {
        return (String) this.requestValidatorConfig.getProperties().get("certificateAlias");
    }

    public String getDefaultAssertionConsumerUrl() {
        return (String) this.requestValidatorConfig.getProperties().get("defaultAssertionConsumerUrl");
    }

    public String getIssuer() {
        return (String) this.requestValidatorConfig.getProperties().get("issuer");
    }

    public boolean isDoValidateSignatureInRequests() {
        return Boolean.parseBoolean(
                (String) this.requestValidatorConfig.getProperties().get("doValidateSignatureInRequests"));
    }

    public boolean isEnableAttributesByDefault() {
        return Boolean
                .parseBoolean((String) this.requestValidatorConfig.getProperties().get("enableAttributesByDefault"));
    }

    public boolean isIdPInitSSOEnabled() {
        return Boolean.parseBoolean((String) this.requestValidatorConfig.getProperties().get("idPInitSSOEnabled"));
    }
}
