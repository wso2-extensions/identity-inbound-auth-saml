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

package org.wso2.carbon.identity.sso.saml;

/**
 * Constants for unit test cases.
 */
public class TestConstants {

    public static final String DEFAULT_SSO_ENCRYPTOR = "org.wso2.carbon.identity.sso.saml.builders.encryption" +
            ".DefaultSSOEncrypter";
    public static final String ASSERTION_ENCRYPTION_ALGO = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    public static final String KEY_ENCRYPTION_ALGO = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

    public static final String SP_ENTITY_ID_WITH_TENANT_DOMAIN = "travelocity.com@tenant.com";
    public static final String SP_ENTITY_ID = "travelocity.com";
    public static final String SP_QUALIFIER = "wso2";
    public static final String SAML_SSO_IDP_URL = "https://localhost:9443/samlsso";
    public static final String BASIC_AUTHN_MODE = "usernamePasswordBasedAuthn";
    public static final String LOACALHOST_DOMAIN = "localhost";
    public static final String TRAVELOCITY_ISSUER = "travelocity.com";
    public static final String WSO2_TENANT_DOMAIN = "wso2.com";
    public static final String TEST_USER_NAME = "testUser";
    public static final String ATTRIBUTE_CONSUMER_INDEX = "1234567890";
    public static final String ACS_URL = "http://localhost.com:8080/travelocity.com/home.jsp";
    public static final String RETURN_TO_URL = "http://localhost.com:8080/travelocity.com/index.jsp";
    public static final String IDP_URL = "https://localhost:9443/commonauth";
    public static final String SAMPLE_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    public static final String SESSION_ID = "sessionId4567890";
    public static final String SAMPLE_SERVER_URL = "https://localhost:9443/server";
    public static final String WSO2_CARBON = "wso2carbon";
    public static final String KEY_STORE_NAME = WSO2_CARBON + ".jks";
    public static final String RSA_SHA1_SIG_ALGO = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    public static final String SHA1_DIGEST_ALGO = "http://www.w3.org/2000/09/xmldsig#sha1";
    public static final String GENERAL_STRING = "WSO2 is an open source technology provider that increases the " +
            "agility of digital businesses and enterprises engaging in digital transformation.";
    public static final String SAML_ECP_ACS_URL = "https://localhost/Shibboleth.sso/SAML2/ECP";
    public static final String SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_NUMERIC = "15";
    public static final String SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_ZERO = "0";
    public static final String SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_ALPHA = "a";
    public static final String SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_EMPTY = "";
    public static final String SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_WHITE_SPACE = " ";
    public static final String IDP_ENTITY_ID_ALIAS = "wso2.is.com";
    public static final String ISSUER_QUALIFIER = "wso2.com";
    public static final String ISSUER_WITH_QUALIFIER= "travelocity.com:urn:qualifier:wso2.com";

    public static final String CLAIM_URI1 = "http://wso2.org/claimuri1";
    public static final String CLAIM_URI2 = "http://wso2.org/claimuri2";
    public static final String CLAIM_VALUE1 = "ClaimValue1";
    public static final String CLAIM_VALUE2 = "ClaimValue2";

    public static final String AUTHN_FAILED_SAML_RESPONSE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<saml2p:Response Destination=\"https://localhost:9443/samlsso\" " +
            "ID=\"_bdcada906cfe9ead0580e5941ab50fe5\" IssueInstant=\"2016-04-23T15:25:27.652Z\" Version=\"2" +
            ".0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer " +
            "Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\" xmlns:saml2=\"urn:oasis:names:tc" +
            ":SAML:2.0:assertion\">localhost</saml2:Issuer><saml2p:Status><saml2p:StatusCode " +
            "Value=\"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed\"/><saml2p:StatusMessage>User " +
            "authentication failed</saml2p:StatusMessage></saml2p:Status></saml2p:Response>";

    public static final String ENCODED_REDIRECT_AUTHN_REQUEST = "nVNdj9owEHzvr4j8Dsnx0YJFOFHQqSddexS4PvTNZzbBnGOn3g3H" +
            "/fvaCZyiqkWor5v1zOzMZHJ7LHR0AIfKmpTddBMWgZF2q0yesqfNXWfEbqcfJigKXfJZRTuzgl8VIEUzRHDkn82twaoAtwZ3UBKeVg" +
            "8p2xGVPI61lULvLFJX2oKPklESkxMH8HNFb2EYK7OFY3ePJYtmRE49VwQNopdwgrwPOykbj4fD4XiQjFm08AqUEVSrDmTYZuPjwaAf" +
            "B82IlkV31kmotacsExqBRfeLlOk97DNVvCghbb4zWZlbLfdK2Ty3OZTZ3uYvpcfw27gUiOoAKSNXheeIlVeFJAylrJfcfOok407v4y" +
            "YZ8X6fDwbdpJ/8ZNHSWbLS6s/+ytrRyhluBSrkRhSAnCRfz74+8F434c/NEvIvm82ys3xcb1j045xMLyTjszLI6ywuQ5UnXjY9JVcL" +
            "dtcDiHO4bPpHYJO4jdjg90r+zUPcL5ZWK/kWzbS2r3MHgt4d8xkUgi6ThonadrJ6lZfhdCQwxKL1MuB/r4RWmQKXsoa97UjvWkvid8" +
            "2nJsO27oYvHcGRorktSuEUBtfhKCT9F0tDwtvIc+1dXUHWgrs6hItrkssA7cehpq/WbUPvQPrLNk4YLK2jJra/6pk23/5lyPScePvv" +
            "n/4G";

    public static final String ENCODED_QUERY_STRING_FOR_AUTHN_REQUEST = "SAMLRequest=nZNbj9owEIXf%2Bysiv0MupSq1SFYUt" +
            "CrStqLA9qFvxplszPqSehyW%2Ffe1E2ijqkWoUp4m42%2BOzxnP7k5KRkewKIzOSTpOSASam1Lop5w87u5HU3JXvJkhU7Kh89bVegM%" +
            "2FWkAXzRHBOn9sYTS2CuwW7FFweNw85KR2rqFxLA1nsjboxtwoOk2mSewsO4KvC%2FcainFtFIwP2JBo6alCM9cpCQAcEuiHyeRtHHQ" +
            "gGhLdG8uh05OTikkEEq2WOXne6wZMIzUYrptKabNX7FA%2FP3Go1KGqKqgPZXmofDeuGaI4wu%2FziC2sNDqmXU6yJH0%2FShP%2F7d" +
            "KUJhlN342nk%2FQ7idbWOMON%2FCh0b1NrNTUMBVLNFCB1nG7nnx9oNk7ovm9C%2Bmm3W482UAoL3JHo28XyLFjuQ9BIO5Ov45rzbFK" +
            "cI%2BlE29sB7JIaKf5IYhYPiT0%2Fa%2BgXj1gt10YK%2FhrNpTQvCwvMeducbaELQjF3fWioiHJUda20CVdHB9rbsF0H%2FteWSVEJ" +
            "sDnppw8dyW61JP6l%2BbyiUHYL4vfTwclFC6MaZgUG1%2BHEQgr%2FMaUfQofkhfSubqAa4G4O4WobpzygfTns6ouxZdg9vz9Q7izT2" +
            "Bjr%2Btj%2Bqqfo%2F%2F3LkOKS%2BPBZFz8B&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&S" +
            "ignature=iTTgVU3p7uy1gaGsK2UXxsfWR9yCQIqfqbOC1rjR8dbw%2BsgAJAtO2fCU91ceI9YvQ1MU0ufOkfAia9zZm27r%2BoyHuF" +
            "kuYBu4CEYFEGr7ZHt8qJCblM8sEvFAWYcNBRv%2BVCVT%2Fk86MeM6x4EBq1e3if63vFoPC1fwNjzOi9D8eV%2FiQ3oXf6ipr27p%2F" +
            "uevNf5ZC%2FWxWsoiPZ9FB7SykZUoYIiO20nctJJL3gCzJTUDbSZbMTDZlJuO1YmEUcI%2Fzs7dbqYidroZ%2FOB%2FpGLYIA95dtln" +
            "yNcNNVym6IzeQwEl7RkbHPO6T7vrIihoLkpLY%2BcSj5xrXei3gWnsNj8wt%2FJLHA%3D%3D";

    public static final String DECODED_REDIRECT_AUTHN_REQUEST = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<samlp:AuthnRequest AssertionConsumerServiceURL=\"http://localhost.com:8080/travelocity.com/index.jsp\" " +
            "AttributeConsumingServiceIndex=\"995559409\" Destination=\"https://localhost:9443/samlsso\" " +
            "ForceAuthn=\"false\" ID=\"ljejfimkiacoghnfpgolcjiioggogepfjogkpaml\" IsPassive=\"true\" " +
            "IssueInstant=\"2017-09-26T08:33:44.030Z\" " +
            "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Version=\"2.0\" " +
            "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
            "<samlp:Issuer xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:assertion\">travelocity.com</samlp:Issuer>" +
            "<saml2p:NameIDPolicy AllowCreate=\"true\" " +
            "Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\" SPNameQualifier=\"Issuer\" " +
            "xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>" +
            "<saml2p:RequestedAuthnContext Comparison=\"exact\" " +
            "xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\">" +
            "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>" +
            "</saml2p:RequestedAuthnContext></samlp:AuthnRequest>";

    public static final String ENCODED_POST_AUTHN_REQUEST = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KP" +
            "HNhbWxwOkF1dGhuUmVxdWVzdCBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHA6Ly9sb2NhbGhvc3QuY29tOjgwODAvdH" +
            "JhdmVsb2NpdHkuY29tL2hvbWUuanNwIiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9sb2NhbGhvc3Q6OTQ0My9zYW1sc3NvIiBGb3JjZUF" +
            "1dGhuPSJmYWxzZSIgSUQ9Im9uaWlvbWFlaWhocG5hbWNpa2ZuZmtwa2xwZGRhZ2loaGhhcGZsYWgiIElzUGFzc2l2ZT0iZmFsc2Ui" +
            "IElzc3VlSW5zdGFudD0iMjAxNy0xMC0xMFQxMTo0NDozNS4yMTRaIiBQcm90b2NvbEJpbmRpbmc9InVybjpvYXNpczpuYW1lczp0Y" +
            "zpTQU1MOjIuMDpiaW5kaW5nczpIVFRQLVBPU1QiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0Yz" +
            "pTQU1MOjIuMDpwcm90b2NvbCI+PHNhbWxwOklzc3VlciB4bWxuczpzYW1scD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF" +
            "zc2VydGlvbiI+dHJhdmVsb2NpdHkuY29tPC9zYW1scDpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53" +
            "My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtP" +
            "SJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaH" +
            "R0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+PGRzOlJlZmVyZW5jZSBVUkk9IiNvbmlpb21hZWloaHB" +
            "uYW1jaWtmbmZrcGtscGRkYWdpaGhoYXBmbGFoIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDov" +
            "L3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0ia" +
            "HR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQW" +
            "xnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT4zNndSZGFDWlE" +
            "1dFZST011Q0l5WHVYV2Q4ZXc9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25h" +
            "dHVyZVZhbHVlPlRPNkNFV3oxVng4NmRuZE9rMzNpS3VuSzFJWlJmRzJ1cU1PY3dLTEl2WEl6aWovVm11VjQ5Y1NsSFBWc2xIV1pMd" +
            "HBzU2VZc0lyQisyUzZmTUs4ZzliQSttRnR6aURKbVhFNUNuT0hEQjd3bTcwRGFJTDZrYUhyWGl6S0RhVmgzdGxaeC9weTlHQTJtU2" +
            "NGdjdyclY1UElvdzhodkpBQVpOVTNmMmdzZjhrUlJVeE9CbFJ0RHZ2Q1VURCtnUlVoVWloaStYMmxkSUFvZHN6QUNuR2c5NVpIRzB" +
            "SVmtXY0RuSndwYm9RbW1pTnNCZGxDdHhsNXBXbHk2VWFKWWR0RzZhWkVTM2JGNmx4RTY2WDY5MUp0VWdZNThxL2p0NzRlekFtdEtx" +
            "STkvUjJ1MnFWMjM0Z0FvM0FrN0xiK3BKNkZDZWFFTFpVRTdCNUJiSFIvTk5MZ0NlUT09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S" +
            "2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlEU1RDQ0FqR2dBd0lCQWdJRUFvTFEvVEFOQmdrcWhraU" +
            "c5dzBCQVFzRkFEQlZNUXN3Q1FZRFZRUUdFd0pWVXpFTE1Ba0dBMVVFQ0JNQ1EwRXhGakFVQmdOVkJBY1REVTF2ZFc1MFlXbHVJRlp" +
            "wWlhjeERUQUxCZ05WQkFvVEJGZFRUekl4RWpBUUJnTlZCQU1UQ1d4dlkyRnNhRzl6ZERBZUZ3MHhOekEzTVRrd05qVXlOVEZhRncw" +
            "eU56QTNNVGN3TmpVeU5URmFNRlV4Q3pBSkJnTlZCQVlUQWxWVE1Rc3dDUVlEVlFRSUV3SkRRVEVXTUJRR0ExVUVCeE1OVFc5MWJuU" +
            "mhhVzRnVm1sbGR6RU5NQXNHQTFVRUNoTUVWMU5QTWpFU01CQUdBMVVFQXhNSmJHOWpZV3hvYjNOME1JSUJJakFOQmdrcWhraUc5dz" +
            "BCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBbHVaRmRXMXluaXR6dGtXTEM2eEtlZ2JSV3hreSs1UDBwNFNoWUVPa0hzMzBRSTJWQ3V" +
            "SNlFvNEJ6NXJUZ0xCcmt5MDNXMUdBVnJaeHV2S1JHajlWOStQbWpkR3RhdTRDVFh1OXBMTGNxbnJ1YWN6b1NkdkJZQTNsUzlhN3pn" +
            "RlUwK3M2a01sMkVoQityazdnWGx1RWVwN2xJT2VuemZsMmY2SW9US2EyZlZnVmQzWUtpU0dzeUw0dHp0Uzcwdm1tWDEyMXFtMHNUS" +
            "mRLV1A0SHhYeXFLOW5lb2xYSTlmWXlIT1lJTFZOWjY5ei83M09PVmhraC9tdlRtV1pMTTdHTTZzQXBteUxYNk9YVXA4ejBwa1krdl" +
            "QvOSt6Unh4UXM3R3VyQzQvQzFuSzNySS8weVNVZ0dFYWZPMWF0TmpZbWxGTitNM3RaWDZuRWNBNmc5NElhdnlRSURBUUFCb3lFd0h" +
            "6QWRCZ05WSFE0RUZnUVV0UzhrSVl4UThVVnZWclpTZGd5aWRlOU9IeFV3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUJmazVtcXNW" +
            "VXJwRkNZVFpaaE94VFJScEdYcW9XMUcwNWJPeEh4czQyUGF4dzhyQUowNlB0eTlqcU0xQ2dSUHBxdlphMmxQUUJRcVpySGtkREUwN" +
            "nE0TkcwRHFNSDhOVCt0TmtYQmU5WVRyZTNFSkNTZnN2c3d0TFZEWjdHRHZUSEtvakpqUXZkVkN6Umo2WEg1VHJ1d2VmYjRCSno5QV" +
            "B0bmx5Skl2akhrMWhkb3pxeU9uaVZaZDBRT3hMQWJjZHQ5NDZjaE5kUXZDbTZhVU9wdXRwOFhvZ3IwS0JuRXkzVThlczJjQWZOWmF" +
            "Fa1BVOFZhNWJVNlhqbnk4ekdRblhDWHhQS3A3c01wZ085M25QQnQvbGlYMXFmeVhNN3hFb3RXb3htbTZIWng4b1dROFU1YWlYalo1" +
            "UktEV0NDcTRadVhsNndWc1V6MWlFNjFzdU81eVdpOD08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5S" +
            "W5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDJwOk5hbWVJRFBvbGljeSBBbGxvd0NyZWF0ZT0idHJ1ZSIgRm9ybWF0PSJ1cm46b2FzaX" +
            "M6bmFtZXM6dGM6U0FNTDoyLjA6bmFtZWlkLWZvcm1hdDpwZXJzaXN0ZW50IiBTUE5hbWVRdWFsaWZpZXI9Iklzc3VlciIgeG1sbnM" +
            "6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiLz48c2FtbDJwOlJlcXVlc3RlZEF1dGhuQ29udGV4" +
            "dCBDb21wYXJpc29uPSJleGFjdCIgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiPjxzY" +
            "W1sOkF1dGhuQ29udGV4dENsYXNzUmVmIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPn" +
            "VybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJhbnNwb3J0PC9zYW1sOkF1dGh" +
            "uQ29udGV4dENsYXNzUmVmPjwvc2FtbDJwOlJlcXVlc3RlZEF1dGhuQ29udGV4dD48L3NhbWxwOkF1dGhuUmVxdWVzdD4=";

    public static final String ENCODED_POST_LOGOUT_REQUEST = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4" +
            "KPHNhbWwycDpMb2dvdXRSZXF1ZXN0IERlc3RpbmF0aW9uPSJodHRwczovL2xvY2FsaG9zdDo5NDQzL3NhbWxzc28iIElEPSJk" +
            "ZGtsZ29lZ29kYWxobmFucHBjZGFnb2JoaGNqbWlkYWplaGRsaWFmIiBJc3N1ZUluc3RhbnQ9IjIwMTctMDktMjZUMDk6Mjc6M" +
            "DYuNDg0WiIgTm90T25PckFmdGVyPSIyMDE3LTA5LTI2VDA5OjMyOjA2LjQ4NFoiIFJlYXNvbj0iU2luZ2xlIExvZ291dCIgVm" +
            "Vyc2lvbj0iMi4wIiB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI+PHNhbWwyOkl" +
            "zc3VlciB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+dHJhdmVsb2NpdHkuY29t" +
            "PC9zYW1sMjpJc3N1ZXI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI" +
            "yI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy" +
            "8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmc" +
            "vMjAwMC8wOS94bWxkc2lnI3JzYS1zaGExIi8+PGRzOlJlZmVyZW5jZSBVUkk9IiNkZGtsZ29lZ29kYWxobmFucHBjZGFnb2Jo" +
            "aGNqbWlkYWplaGRsaWFmIj48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vc" +
            "mcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3" +
            "d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PC9kczpUcmFuc2Zvcm1zPjxkczpEaWdlc3RNZXRob2QgQWxnb3J" +
            "pdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjc2hhMSIvPjxkczpEaWdlc3RWYWx1ZT4zNTczajNIeXhr" +
            "TUlkNlZVQ2JCdWFrWDI1OVE9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ" +
            "25hdHVyZVZhbHVlPlk2WURuSkZFRmE4a0c0M203YUl0VjhkQmlSbEsveGduZ3Q3VDBYM2UrMTFDMUtYRHZEK3cya09uTHU0TT" +
            "haTzdNbjduV014MFF5dzMyQ0JsKzRaODZ3SzhiNmFHUVliSjZxbTI2SlZCZFJLQWhZYUN4bExiVlJNUkRXR25EMWR0Y3pSNVN" +
            "SOFhaQlh5VUFhMHV0bXpqQlhmSXZpMHZEek5vQnFQZ00wdFVSSjVqTVF0TVZkRTF3cFhPODlMN1ViNE0vQ0t5Mm9vRHJTQ21X" +
            "MHNnUUNmaTlHeTFwZU5ma0VuK3RjZlhqejloQWIxd0lLZzlhb1Z2cnRoblNrOVVQTGlMQWdNNzVlUUw2VmlqdWE1WlhhZ216Y" +
            "TRqNUgwR3VqRU44eUNackV6Z1c0aFpOeDRPVmlEMWV1WWp4TlNRNHRxa2VvZUlENXRGdDlEeHJVWnNWdGlXdz09PC9kczpTaW" +
            "duYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlEU1RDQ0FqR2dBd0l" +
            "CQWdJRUFvTFEvVEFOQmdrcWhraUc5dzBCQVFzRkFEQlZNUXN3Q1FZRFZRUUdFd0pWVXpFTE1Ba0dBMVVFQ0JNQ1EwRXhGakFV" +
            "QmdOVkJBY1REVTF2ZFc1MFlXbHVJRlpwWlhjeERUQUxCZ05WQkFvVEJGZFRUekl4RWpBUUJnTlZCQU1UQ1d4dlkyRnNhRzl6Z" +
            "ERBZUZ3MHhOekEzTVRrd05qVXlOVEZhRncweU56QTNNVGN3TmpVeU5URmFNRlV4Q3pBSkJnTlZCQVlUQWxWVE1Rc3dDUVlEVl" +
            "FRSUV3SkRRVEVXTUJRR0ExVUVCeE1OVFc5MWJuUmhhVzRnVm1sbGR6RU5NQXNHQTFVRUNoTUVWMU5QTWpFU01CQUdBMVVFQXh" +
            "NSmJHOWpZV3hvYjNOME1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBbHVaRmRXMXluaXR6dGtX" +
            "TEM2eEtlZ2JSV3hreSs1UDBwNFNoWUVPa0hzMzBRSTJWQ3VSNlFvNEJ6NXJUZ0xCcmt5MDNXMUdBVnJaeHV2S1JHajlWOStQb" +
            "WpkR3RhdTRDVFh1OXBMTGNxbnJ1YWN6b1NkdkJZQTNsUzlhN3pnRlUwK3M2a01sMkVoQityazdnWGx1RWVwN2xJT2VuemZsMm" +
            "Y2SW9US2EyZlZnVmQzWUtpU0dzeUw0dHp0Uzcwdm1tWDEyMXFtMHNUSmRLV1A0SHhYeXFLOW5lb2xYSTlmWXlIT1lJTFZOWjY" +
            "5ei83M09PVmhraC9tdlRtV1pMTTdHTTZzQXBteUxYNk9YVXA4ejBwa1krdlQvOSt6Unh4UXM3R3VyQzQvQzFuSzNySS8weVNV" +
            "Z0dFYWZPMWF0TmpZbWxGTitNM3RaWDZuRWNBNmc5NElhdnlRSURBUUFCb3lFd0h6QWRCZ05WSFE0RUZnUVV0UzhrSVl4UThVV" +
            "nZWclpTZGd5aWRlOU9IeFV3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUJmazVtcXNWVXJwRkNZVFpaaE94VFJScEdYcW9XMU" +
            "cwNWJPeEh4czQyUGF4dzhyQUowNlB0eTlqcU0xQ2dSUHBxdlphMmxQUUJRcVpySGtkREUwNnE0TkcwRHFNSDhOVCt0TmtYQmU" +
            "5WVRyZTNFSkNTZnN2c3d0TFZEWjdHRHZUSEtvakpqUXZkVkN6Umo2WEg1VHJ1d2VmYjRCSno5QVB0bmx5Skl2akhrMWhkb3px" +
            "eU9uaVZaZDBRT3hMQWJjZHQ5NDZjaE5kUXZDbTZhVU9wdXRwOFhvZ3IwS0JuRXkzVThlczJjQWZOWmFFa1BVOFZhNWJVNlhqb" +
            "nk4ekdRblhDWHhQS3A3c01wZ085M25QQnQvbGlYMXFmeVhNN3hFb3RXb3htbTZIWng4b1dROFU1YWlYalo1UktEV0NDcTRadV" +
            "hsNndWc1V6MWlFNjFzdU81eVdpOD08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2R" +
            "zOlNpZ25hdHVyZT48c2FtbDI6TmFtZUlEIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3Jt" +
            "YXQ6ZW50aXR5IiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+ZWdvbkBnb3QuY" +
            "29tQGlzLmNvbTwvc2FtbDI6TmFtZUlEPjxzYW1sMnA6U2Vzc2lvbkluZGV4PjhjODM1NGQ1LTRlZWEtNDk0Mi04NjUxLWNlMT" +
            "JmYTQ2MjZlYTwvc2FtbDJwOlNlc3Npb25JbmRleD48L3NhbWwycDpMb2dvdXRSZXF1ZXN0Pg==";

    public static final String DECODED_POST_LOGOUT_REQUEST = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<saml2p:LogoutRequest Destination=\"https://localhost:9443/samlsso\" " +
            "ID=\"ddklgoegodalhnanppcdagobhhcjmidajehdliaf\" IssueInstant=\"2017-09-26T09:27:06.484Z\" " +
            "NotOnOrAfter=\"2017-09-26T09:32:06.484Z\" Reason=\"Single Logout\" Version=\"2.0\" " +
            "xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer " +
            "xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">travelocity.com</saml2:Issuer>" +
            "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo>" +
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference " +
            "URI=\"#ddklgoegodalhnanppcdagobhhcjmidajehdliaf\"><ds:Transforms><ds:Transform " +
            "Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform " +
            "Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod " +
            "Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>3573j3HyxkMId6VUCbBuakX259Q=" +
            "</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Y6YDnJFEFa8kG43m7aItV8dBiRlK" +
            "/xgngt7T0X3e+11C1KXDvD+w2kOnLu4M8ZO7Mn7nWMx0Qyw32CBl+4Z86wK8b6aGQYbJ6qm26JVBdRKAhYaCxlLbVRMRDWG" +
            "nD1dtczR5SR8XZBXyUAa0utmzjBXfIvi0vDzNoBqPgM0tURJ5jMQtMVdE1wpXO89L7Ub4M/CKy2ooDrSCmW0sgQCfi9Gy1p" +
            "eNfkEn+tcfXjz9hAb1wIKg9aoVvrthnSk9UPLiLAgM75eQL6Vijua5ZXagmza4j5H0GujEN8yCZrEzgW4hZNx4OViD1euYj" +
            "xNSQ4tqkeoeID5tFt9DxrUZsVtiWw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>" +
            "MIIDSTCCAjGgAwIBAgIEAoLQ/TANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAc" +
            "TDU1vdW50YWluIFZpZXcxDTALBgNVBAoTBFdTTzIxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0xNzA3MTkwNjUyNTFaFw0yNz" +
            "A3MTcwNjUyNTFaMFUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzENMAsGA1UEC" +
            "hMEV1NPMjESMBAGA1UEAxMJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAluZFdW1ynitztkWL" +
            "C6xKegbRWxky+5P0p4ShYEOkHs30QI2VCuR6Qo4Bz5rTgLBrky03W1GAVrZxuvKRGj9V9+PmjdGtau4CTXu9pLLcqnruacz" +
            "oSdvBYA3lS9a7zgFU0+s6kMl2EhB+rk7gXluEep7lIOenzfl2f6IoTKa2fVgVd3YKiSGsyL4tztS70vmmX121qm0sTJdKWP" +
            "4HxXyqK9neolXI9fYyHOYILVNZ69z/73OOVhkh/mvTmWZLM7GM6sApmyLX6OXUp8z0pkY+vT/9+zRxxQs7GurC4/C1nK3rI" +
            "/0ySUgGEafO1atNjYmlFN+M3tZX6nEcA6g94IavyQIDAQABoyEwHzAdBgNVHQ4EFgQUtS8kIYxQ8UVvVrZSdgyide9OHxUw" +
            "DQYJKoZIhvcNAQELBQADggEBABfk5mqsVUrpFCYTZZhOxTRRpGXqoW1G05bOxHxs42Paxw8rAJ06Pty9jqM1CgRPpqvZa2l" +
            "PQBQqZrHkdDE06q4NG0DqMH8NT+tNkXBe9YTre3EJCSfsvswtLVDZ7GDvTHKojJjQvdVCzRj6XH5Truwefb4BJz9APtnlyJ" +
            "IvjHk1hdozqyOniVZd0QOxLAbcdt946chNdQvCm6aUOputp8Xogr0KBnEy3U8es2cAfNZaEkPU8Va5bU6Xjny8zGQnXCXxP" +
            "Kp7sMpgO93nPBt/liX1qfyXM7xEotWoxmm6HZx8oWQ8U5aiXjZ5RKDWCCq4ZuXl6wVsUz1iE61suO5yWi8=</ds:X509Cer" +
            "tificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:NameID " +
            "Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\" " +
            "xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">egon@got.com@is.com</saml2:NameID>" +
            "<saml2p:SessionIndex>8c8354d5-4eea-4942-8651-ce12fa4626ea</saml2p:SessionIndex></saml2p:LogoutRequest>";

    public static final String ENCODED_REDIRECT_LOGOUT_REQUEST = "nZJLa8MwEITv/RVGdye249S2iB0CoRDoA5q0h94Ua/1ILa2rV" +
            "Ur77ysnTZ/QQ0HosMx+zAw7m7+oznsGQy3qnIWjgHmgS5StrnN2t7nwUzYvzmYkVBf1/BJr3NtbeNoDWW/pvlYLe1htrO2Jj8cdlqJ" +
            "rkCzP4ngyHhaJkHmrZc4e+1L2XdeoWukd9Eo2VV01rcRdKYWq6ma3BXxE5dREe1hpskLbnEVBmPhh4N4mSHkc8Uk0CtP4gXnXaG/0j" +
            "VlUFswvXfKpuwVBg8u1y9WBd8zBvPtT8GgI7qrQxI9Rc7Y3mqOglrgWCojbkq8XV5fcSXlv0GKJHSuOzfCDX/OV8DdAEIEZimOFNeI" +
            "ZXGutfR2VqGbjr8QT/9oRVkvvAo0S9m/0MGmlXx2kHLR1YPYvZ0KqVp/8HB0Up0tYAw3NrbSEl0JOk22anUd+sq0CP5aQ+WmSTf1tI" +
            "CciDKHKouk758fmx/TbZRVv";

    public static final String ENCODED_QUERY_STRING_FOR_REDIRECT_LOGOUT_REQUEST = "SAMLRequest=nZJLa8MwEITv%2FRVGdy" +
            "e249S2iB0CoRDoA5q0h94Ua%2F1ILa2rVUr77ysnTZ%2FQQ0HosMx%2BzAw7m7%2BoznsGQy3qnIWjgHmgS5StrnN2t7nwUzYvzmYk" +
            "VBf1%2FBJr3NtbeNoDWW%2FpvlYLe1htrO2Jj8cdlqJrkCzP4ngyHhaJkHmrZc4e%2B1L2XdeoWukd9Eo2VV01rcRdKYWq6ma3BXxE" +
            "5dREe1hpskLbnEVBmPhh4N4mSHkc8Uk0CtP4gXnXaG%2F0jVlUFswvXfKpuwVBg8u1y9WBd8zBvPtT8GgI7qrQxI9Rc7Y3mqOglrgW" +
            "Cojbkq8XV5fcSXlv0GKJHSuOzfCDX%2FOV8DdAEIEZimOFNeIZXGutfR2VqGbjr8QT%2F9oRVkvvAo0S9m%2F0MGmlXx2kHLR1YPYv" +
            "Z0KqVp%2F8HB0Up0tYAw3NrbSEl0JOk22anUd%2Bsq0CP5aQ%2BWmSTf1tICciDKHKouk758fmx%2FTbZRVv&SigAlg=http%3A%2F" +
            "%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=aiBu%2Bj6WVD5Ph8rm1Df75KZwNQTobwiGPL8M6UtIH3g" +
            "R2Q%2FzMScrBr9L2x9mHhjWvpRi7eLAXPxt40dD2naSSjDyVTRI%2FhbE8kRAHo7%2FNxUmelsYnsGnuVbJhZTDRD0CvD1hmhdigvt" +
            "cqCVFngYf6BjG2O%2FAaWdwl%2BZKqWnLrNxYubYPRSNE9po3SOV4OvZOdAWrJcnz4%2F9EdcF1FXWgosNhSeDEBms%2Bee0Hdg3Dl" +
            "4yw04nUgT%2FGg3CNu78WW4VR%2FbX9ip5batCvBNbQviJJl0cSThI9NL4qjgrliP%2Fy6y9XEA2KsydV%2BmvJVouSuQMejwpAxRb" +
            "jz2Qto0ABA6B1fg%3D%3D";
    public static final String SOAP_DECODED_SAML_REQUEST = "PHNhbWxwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1scD0idXJuOm9hc2l" +
            "zOm5hbWVzOnRjOlNBTUw6Mi4wOnByb3RvY29sIiBBc3NlcnRpb25Db25zdW1lclNlcnZpY2VVUkw9Imh0dHBzOi8vbG9jYWxob3N0L" +
            "1NoaWJib2xldGguc3NvL1NBTUwyL0VDUCIgSUQ9Il9lYzEwMjVlNzg2ZTZmZmYyMDZlZjYzOTA5MDI5MjAyYSIgSXNzdWVJbnN0YW5" +
            "0PSIyMDE4LTEwLTIyVDExOjQxOjEwWiIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ" +
            "3M6UEFPUyIgVmVyc2lvbj0iMi4wIj48c2FtbDpJc3N1ZXIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmF" +
            "zc2VydGlvbiI+aHR0cHM6Ly9sb2NhbGhvc3Qvc2hpYmJvbGV0aDwvc2FtbDpJc3N1ZXI+PHNhbWxwOk5hbWVJRFBvbGljeSBBbGxvd" +
            "0NyZWF0ZT0iMSIvPjxzYW1scDpTY29waW5nPjxzYW1scDpJRFBMaXN0PjxzYW1scDpJRFBFbnRyeSBQcm92aWRlcklEPSJodHRwczo" +
            "vL2lkcC5pcy5jb20iLz48L3NhbWxwOklEUExpc3Q+PC9zYW1scDpTY29waW5nPjwvc2FtbHA6QXV0aG5SZXF1ZXN0Pg==";
    public static final String SOAP_FAULT = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/en"+
            "velope/\"><SOAP-ENV:Header/><SOAP-ENV:Body><SOAP-ENV:Fault><faultcode>SOAP-ENV:Client</faultcode><faul"+
            "tstring>An error Occured</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>";
    public static final String SOAP_FAULT_ELEMENT = "<SOAP-ENV:Fault xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/so"+
            "ap/envelope/\"><faultcode>SOAP-ENV:Client</faultcode><faultstring>An error Occured</faultstring></SOAP"+
            "-ENV:Fault>";
    public static final String AUTHN_SUCCESS_SAML_RESPONSE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Header><ecp:Response xmlns:ecp=\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\" AssertionConsumerServiceURL=\"https://localhost/Shibboleth.sso/SAML2/ECP\" SOAP-ENV:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" SOAP-ENV:mustUnderstand=\"1\"/></SOAP-ENV:Header><SOAP-ENV:Body>\n" +
            "<saml2p:Response Destination=\"https://localhost/Shibboleth.sso/SAML2/ECP\" ID=\"_09ae18bde316aa46d07589a301c93cbf\" InResponseTo=\"_ec1025e786e6fff206ef63909029202a\" IssueInstant=\"2018-10-22T11:41:12.905Z\" Version=\"2.0\" xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">https://idp.is.com</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></saml2p:Status><saml2:Assertion ID=\"_eba06643695146544e55bd322c9f3a94\" IssueInstant=\"2018-10-22T11:41:12.906Z\" Version=\"2.0\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://idp.is.com</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "<ds:SignedInfo>\n" +
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
            "<ds:Reference URI=\"#_eba06643695146544e55bd322c9f3a94\">\n" +
            "<ds:Transforms>\n" +
            "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "</ds:Transforms>\n" +
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n" +
            "<ds:DigestValue>EmXowTV9xjRjVyuQKEr6nT5lSeQ=</ds:DigestValue>\n" +
            "</ds:Reference>\n" +
            "</ds:SignedInfo>\n" +
            "<ds:SignatureValue>\n" +
            "MsXcTikjZvPKve5z04+LdNnJV2mN4gVXDuS0t2jTovmW33Xwm/ZX0u+cbwZfN3oIlEgdcXGry4nZ\n" +
            "+M53o7ER5qiwtTGZcyUCBINYJoIZL3+ZCTnqCdrK7N8KGX2NXOplHF3b+oyMC8NR3uWO3vYkNsY9\n" +
            "EBIy5bpzI2VW8gCFxm/HMiXSJcK29gRWAQ03j5TEeine/2BSkeVTihgcl1vWFQF5LnyiqhOLpm8c\n" +
            "9c+Nxh1O/SfE2F41C9InclePMcsTDfz3y/sMQ7AM+yETo0EhWKtXsiy72PGRJsxgZg2lxydDPnef\n" +
            "q3ttq233+WljMUIu1t8yHUFDWPScoSVpcE87dg==\n" +
            "</ds:SignatureValue>\n" +
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSTCCAjGgAwIBAgIEAoLQ/TANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzELMAkGA1UE\n" +
            "CBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxDTALBgNVBAoTBFdTTzIxEjAQBgNVBAMTCWxv\n" +
            "Y2FsaG9zdDAeFw0xNzA3MTkwNjUyNTFaFw0yNzA3MTcwNjUyNTFaMFUxCzAJBgNVBAYTAlVTMQsw\n" +
            "CQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzENMAsGA1UEChMEV1NPMjESMBAGA1UE\n" +
            "AxMJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAluZFdW1ynitztkWL\n" +
            "C6xKegbRWxky+5P0p4ShYEOkHs30QI2VCuR6Qo4Bz5rTgLBrky03W1GAVrZxuvKRGj9V9+PmjdGt\n" +
            "au4CTXu9pLLcqnruaczoSdvBYA3lS9a7zgFU0+s6kMl2EhB+rk7gXluEep7lIOenzfl2f6IoTKa2\n" +
            "fVgVd3YKiSGsyL4tztS70vmmX121qm0sTJdKWP4HxXyqK9neolXI9fYyHOYILVNZ69z/73OOVhkh\n" +
            "/mvTmWZLM7GM6sApmyLX6OXUp8z0pkY+vT/9+zRxxQs7GurC4/C1nK3rI/0ySUgGEafO1atNjYml\n" +
            "FN+M3tZX6nEcA6g94IavyQIDAQABoyEwHzAdBgNVHQ4EFgQUtS8kIYxQ8UVvVrZSdgyide9OHxUw\n" +
            "DQYJKoZIhvcNAQELBQADggEBABfk5mqsVUrpFCYTZZhOxTRRpGXqoW1G05bOxHxs42Paxw8rAJ06\n" +
            "Pty9jqM1CgRPpqvZa2lPQBQqZrHkdDE06q4NG0DqMH8NT+tNkXBe9YTre3EJCSfsvswtLVDZ7GDv\n" +
            "THKojJjQvdVCzRj6XH5Truwefb4BJz9APtnlyJIvjHk1hdozqyOniVZd0QOxLAbcdt946chNdQvC\n" +
            "m6aUOputp8Xogr0KBnEy3U8es2cAfNZaEkPU8Va5bU6Xjny8zGQnXCXxPKp7sMpgO93nPBt/liX1\n" +
            "qfyXM7xEotWoxmm6HZx8oWQ8U5aiXjZ5RKDWCCq4ZuXl6wVsUz1iE61suO5yWi8=</ds:X509Certi" +
            "ficate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID " +
            "Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">admin</saml2" +
            ":NameID><saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bea" +
            "rer\"><saml2:SubjectConfirmationData InResponseTo=\"_ec1025e786e6fff206ef63909" +
            "029202a\" NotOnOrAfter=\"2018-10-22T11:46:12.905Z\" Recipient=\"https://localh" +
            "ost/Shibboleth.sso/SAML2/ECP\"/></saml2:SubjectConfirmation></saml2:Subject><s" +
            "aml2:Conditions NotBefore=\"2018-10-22T11:41:12.906Z\" NotOnOrAfter=\"2018-10-" +
            "22T11:46:12.905Z\"><saml2:AudienceRestriction><saml2:Audience>https://localhos" +
            "t/shibboleth</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><s" +
            "aml2:AuthnStatement AuthnInstant=\"2018-10-22T11:41:12.910Z\" SessionIndex=\"1" +
            "c6225a6-3102-439c-9183-aa5dafae0765\"><saml2:AuthnContext><saml2:AuthnContextC" +
            "lassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextCla" +
            "ssRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:R" +
            "esponse></SOAP-ENV:Body></SOAP-ENV:Envelope>";
    public static final String SOAP_MESSAGE = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><SOAP-EN" +
            "V:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-" +
            "ENV:Header><ecp:Response xmlns:ecp=\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:" +
            "ecp\" AssertionConsumerServiceURL=\"https://localhost/Shibboleth.sso/SAML2/ECP" +
            "\" SOAP-ENV:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" SOAP-ENV:must" +
            "Understand=\"1\"/></SOAP-ENV:Header><SOAP-ENV:Body><?xml version=\"1.0\" encod" +
            "ing=\"UTF-8\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/" +
            "soap/envelope/\"><SOAP-ENV:Header><ecp:Response xmlns:ecp=\"urn:oasis:names:tc" +
            ":SAML:2.0:profiles:SSO:ecp\" AssertionConsumerServiceURL=\"https://localhost/S" +
            "hibboleth.sso/SAML2/ECP\" SOAP-ENV:actor=\"http://schemas.xmlsoap.org/soap/act" +
            "or/next\" SOAP-ENV:mustUnderstand=\"1\"/></SOAP-ENV:Header><SOAP-ENV:Body>\n"   +
            "<saml2p:Response Destination=\"https://localhost/Shibboleth.sso/SAML2/ECP\" ID" +
            "=\"_09ae18bde316aa46d07589a301c93cbf\" InResponseTo=\"_ec1025e786e6fff206ef639" +
            "09029202a\" IssueInstant=\"2018-10-22T11:41:12.905Z\" Version=\"2.0\" xmlns:sa" +
            "ml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2:Issuer Format=\"urn:oasis" +
            ":names:tc:SAML:2.0:nameid-format:entity\" xmlns:saml2=\"urn:oasis:names:tc:SAM" +
            "L:2.0:assertion\">https://idp.is.com</saml2:Issuer><saml2p:Status><saml2p:Stat" +
            "usCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></saml2p:Status><" +
            "saml2:Assertion ID=\"_eba06643695146544e55bd322c9f3a94\" IssueInstant=\"2018-1" +
            "0-22T11:41:12.906Z\" Version=\"2.0\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0" +
            ":assertion\"><saml2:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:" +
            "entity\">https://idp.is.com</saml2:Issuer><ds:Signature xmlns:ds=\"http://www." +
            "w3.org/2000/09/xmldsig#\">\n" +
            "<ds:SignedInfo>\n" +
            "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" +
            "<ds:Reference URI=\"#_eba06643695146544e55bd322c9f3a94\">\n" +
            "<ds:Transforms>\n" +
            "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n" +
            "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "</ds:Transforms>\n" +
            "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n" +
            "<ds:DigestValue>EmXowTV9xjRjVyuQKEr6nT5lSeQ=</ds:DigestValue>\n" +
            "</ds:Reference>\n" +
            "</ds:SignedInfo>\n" +
            "<ds:SignatureValue>\n" +
            "MsXcTikjZvPKve5z04+LdNnJV2mN4gVXDuS0t2jTovmW33Xwm/ZX0u+cbwZfN3oIlEgdcXGry4nZ\n" +
            "+M53o7ER5qiwtTGZcyUCBINYJoIZL3+ZCTnqCdrK7N8KGX2NXOplHF3b+oyMC8NR3uWO3vYkNsY9\n" +
            "EBIy5bpzI2VW8gCFxm/HMiXSJcK29gRWAQ03j5TEeine/2BSkeVTihgcl1vWFQF5LnyiqhOLpm8c\n" +
            "9c+Nxh1O/SfE2F41C9InclePMcsTDfz3y/sMQ7AM+yETo0EhWKtXsiy72PGRJsxgZg2lxydDPnef\n" +
            "q3ttq233+WljMUIu1t8yHUFDWPScoSVpcE87dg==\n" +
            "</ds:SignatureValue>\n" +
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSTCCAjGgAwIBAgIEAoLQ/TANBgkqhkiG9w0BAQsFADBVMQswCQYDVQQGEwJVUzELMAkGA1UE\n" +
            "CBMCQ0ExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxDTALBgNVBAoTBFdTTzIxEjAQBgNVBAMTCWxv\n" +
            "Y2FsaG9zdDAeFw0xNzA3MTkwNjUyNTFaFw0yNzA3MTcwNjUyNTFaMFUxCzAJBgNVBAYTAlVTMQsw\n" +
            "CQYDVQQIEwJDQTEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzENMAsGA1UEChMEV1NPMjESMBAGA1UE\n" +
            "AxMJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAluZFdW1ynitztkWL\n" +
            "C6xKegbRWxky+5P0p4ShYEOkHs30QI2VCuR6Qo4Bz5rTgLBrky03W1GAVrZxuvKRGj9V9+PmjdGt\n" +
            "au4CTXu9pLLcqnruaczoSdvBYA3lS9a7zgFU0+s6kMl2EhB+rk7gXluEep7lIOenzfl2f6IoTKa2\n" +
            "fVgVd3YKiSGsyL4tztS70vmmX121qm0sTJdKWP4HxXyqK9neolXI9fYyHOYILVNZ69z/73OOVhkh\n" +
            "/mvTmWZLM7GM6sApmyLX6OXUp8z0pkY+vT/9+zRxxQs7GurC4/C1nK3rI/0ySUgGEafO1atNjYml\n" +
            "FN+M3tZX6nEcA6g94IavyQIDAQABoyEwHzAdBgNVHQ4EFgQUtS8kIYxQ8UVvVrZSdgyide9OHxUw\n" +
            "DQYJKoZIhvcNAQELBQADggEBABfk5mqsVUrpFCYTZZhOxTRRpGXqoW1G05bOxHxs42Paxw8rAJ06\n" +
            "Pty9jqM1CgRPpqvZa2lPQBQqZrHkdDE06q4NG0DqMH8NT+tNkXBe9YTre3EJCSfsvswtLVDZ7GDv\n" +
            "THKojJjQvdVCzRj6XH5Truwefb4BJz9APtnlyJIvjHk1hdozqyOniVZd0QOxLAbcdt946chNdQvC\n" +
            "m6aUOputp8Xogr0KBnEy3U8es2cAfNZaEkPU8Va5bU6Xjny8zGQnXCXxPKp7sMpgO93nPBt/liX1\n" +
            "qfyXM7xEotWoxmm6HZx8oWQ8U5aiXjZ5RKDWCCq4ZuXl6wVsUz1iE61suO5yWi8=</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">admin</saml2:NameID><saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml2:SubjectConfirmationData InResponseTo=\"_ec1025e786e6fff206ef63909029202a\" NotOnOrAfter=\"2018-10-22T11:46:12.905Z\" Recipient=\"https://localhost/Shibboleth.sso/SAML2/ECP\"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore=\"2018-10-22T11:41:12.906Z\" NotOnOrAfter=\"2018-10-22T11:46:12.905Z\"><saml2:AudienceRestriction><saml2:Audience>https://localhost/shibboleth</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant=\"2018-10-22T11:41:12.910Z\" SessionIndex=\"1c6225a6-3102-439c-9183-aa5dafae0765\"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response></SOAP-ENV:Body></SOAP-ENV:Envelope></SOAP-ENV:Body></SOAP-ENV:Envelope>";
}
