package org.wso2.carbon.identity.saml.util;


public enum SAML2URI {

    NAMEID_FORMAT_ENTITY_IDENTIFIER("urn:oasis:names:tc:SAML:2.0:nameid-format:entity"),
    STATUS_CODE_VERSION_MISMATCH("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"),
    STATUS_CODE_REQUESTER("urn:oasis:names:tc:SAML:2.0:status:Requester");

    private String value;

    SAML2URI(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return this.value;
    }
}
