package org.wso2.carbon.identity.saml.wrapper;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class SAMLValidatorConfig implements Serializable {

    private static final long serialVersionUID = 1926448600042806841L;
    private Properties properties;

    public SAMLValidatorConfig(Properties properties) {
        this.properties = properties;
    }

    public List<String> getAssertionConsumerUrlList() {
        List assertionConsumerUrls = (List) this.properties.get("assertionConsumerUrls");
        List<String> assertionConsumerUrlStrings = new ArrayList<String>();
        assertionConsumerUrls.stream().forEach(a -> assertionConsumerUrlStrings.add((String)a));
        return assertionConsumerUrlStrings;
    }

    public String getIssuer() {
        return (String) properties.get("issuer");
    }

    public String getCertAlias() {
        return (String) properties.get("certificateAlias");
    }

    public boolean isEnableAttributesByDefault() {
        return Boolean.parseBoolean((String) properties.get("enableAttributesByDefault"));
    }

    public boolean isIdPInitSSOEnabled(){
        return Boolean.parseBoolean((String) properties.get("idPInitSSOEnabled"));
    }

    public boolean isDoValidateSignatureInRequests () {
        return Boolean.parseBoolean((String) properties.get("doValidateSignatureInRequests"));
    }

    public String getDefaultAssertionConsumerUrl() {
        return (String) properties.get("defaultAssertionConsumerUrl");
    }

    public String getAttributeConsumingServiceIndex() {
        return (String) properties.get("attributeConsumingServiceIndex");
    }
}
