/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.auth.saml2.common;

import java.io.File;

/**
 * Bean class that represents the carbon server's key store configuration.
 * This class must read configuration from deployment.yaml.
 */
public class KeyStoreConfig {

    private static volatile KeyStoreConfig instance = new KeyStoreConfig();

    private KeyStoreConfig() {

    }

    public static KeyStoreConfig getInstance() {
        return instance;
    }

    private String keyStoreLocation = System.getProperty("carbon.home") + File.separator + "resources" + File.separator
                                      + "security" + File.separator + "wso2carbon.jks";
    private String keyStoreType = "JKS";
    private String keyStorePassword = "wso2carbon";
    private String keyStoreAlias = "wso2carbon";

    public String getKeyStoreLocation() {
        return keyStoreLocation;
    }

    public void setKeyStoreLocation(String keyStoreLocation) {
        this.keyStoreLocation = keyStoreLocation;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getKeyStoreAlias() {
        return keyStoreAlias;
    }

    public void setKeyStoreAlias(String keyStoreAlias) {
        this.keyStoreAlias = keyStoreAlias;
    }
}
