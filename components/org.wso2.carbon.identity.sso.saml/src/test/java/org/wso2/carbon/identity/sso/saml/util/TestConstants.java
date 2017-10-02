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

package org.wso2.carbon.identity.sso.saml.util;

/**
 * Constants for unit test cases.
 */
public class TestConstants {

    public static final String LOACALHOST_DOMAIN = "localhost";

    public static final String GENERAL_STRING = "kjladf jhadkjf kjhjkadf. adkjfa jdafkjhd. jhdafkjhd" +
            "lkadflkjdaf lkjdf  lkjdalkf.";

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

    public static final String ENCODED_POST_AUTHN_REQUEST = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4" +
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

    public static final String DECODED_POST_AUTHN_REQUEST = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
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
}
