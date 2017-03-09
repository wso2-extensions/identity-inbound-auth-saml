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

package org.wso2.carbon.identity.saml.inbound.test.module;

public class SAMLInboundTestConstants {

    public static final String SAML_REQUEST_INVALID_SIGNATURE =
            "nVNdj9owEPwrkd8hIVLvwCKcKOhUpGubQq4PffOZDTF1vKnX4ePf10lIRasWob6uZ2dnZ9bTp1OpgwNYUmgSNhpGLAAjcavMLmGv2fNgzJ5mUxKlrvi8doVZw48ayAW%2BzxBvHxJWW8NRkCJuRAnEneSb%2BccXHg8jXll0KFGzYE4E1vlBCzRUl2A3YA9Kwuv6JWGFcxUPQ41S6ALJ8XE0jkJnxQF8TbnzUGIZFljCcE8VC5ZehDLCtbqbZvqtexJP4nAnHBzFmQXPaCW08hOWC03AgtUyYdpoFLjHqtqBFghqhzstZJ5XWhVv%2B%2B9aqAKhNB5NqSBSB0iYs3XTTlTDypATxiUsjkaPgygexI%2FZKObxA38XDSfRwzcWpJft3yvTeXrLqrcORPxDlqWD9PMmY8HXPhsPYH0S7XR7fwaid57N%2FnB0Gl4zdvxxxT95itUyRa3k%2BWpMfH%2FWWuNxYcEn0FvmQyiFu03QVNR2kLdQXjW7kwPjWLBJG01faqFVrsAmrFPMwl%2BaL5cJ2zZof2MOTu6%2FxC%2BwrIRV1NgOJyHdxXh%2BzbzQ3tU15FcT7g7hJkxy2VD7cnNzR7Tb5ohA%2Bs0yKwxVaF0X21%2F1zLq3fxky6xO%2F%2Fs2znw%3D%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1&Signature=jYIfq5HEdqzRasdfasdI9xTbrA15E95L2SXKJRgrX%2FLr0uGIe43hwsyjETbbU3F0%2F0sc53lZwibpS0aP2Ec15sZZR4%2B0iB3vDVYX8k%2Bb%2FNISed7D0kcniK5naVBjeBsNdGK6vAxTQSGxs0W4cXzdZQ%2FAinT5iRYmsVW%2BOmLpcP2U%3D";

    public static final String SAML_POST_REQUEST =
            "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbHA6QXV0aG5SZXF1ZXN0IHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIEFzc2VydGlvbkNvbnN1bWVyU2VydmljZVVSTD0iaHR0cDovL2xvY2FsaG9zdDo4MDgwL3RyYXZlbG9jaXR5LmNvbS9ob21lLmpzcCIgRGVzdGluYXRpb249Imh0dHBzOi8vbG9jYWxob3N0OjkyOTIvZ2F0ZXdheSIgRm9yY2VBdXRobj0iZmFsc2UiIElEPSJrY2xwamllaGJwb2FhbWhsbW9hYnBhaXBwbGphZmFtZmVjb25tYmhnIiBJc1Bhc3NpdmU9ImZhbHNlIiBJc3N1ZUluc3RhbnQ9IjIwMTctMDMtMDZUMTQ6MTc6MjEuNzIzWiIgUHJvdG9jb2xCaW5kaW5nPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YmluZGluZ3M6SFRUUC1QT1NUIiBWZXJzaW9uPSIyLjAiPjxzYW1scDpJc3N1ZXIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPnRyYXZlbG9jaXR5LmNvbTwvc2FtbHA6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Etc2hhMSIvPjxkczpSZWZlcmVuY2UgVVJJPSIja2NscGppZWhicG9hYW1obG1vYWJwYWlwcGxqYWZhbWZlY29ubWJoZyI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI3NoYTEiLz48ZHM6RGlnZXN0VmFsdWU+akx5MlVWcmVTSXN2QUtSVlZWVzVubVppb2V3PTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5NUkFickZWRXlzRUVSRTBKaTdZVGdrNTYvdHo0SEhYVWg0eERxWE9tc2o3ckdzdVBkWUNTQXBka0FNZUhTbTVpb3dkM0RDbERlYndBT3NEU21VVmhRa1g5VUhMQ1E3bUZ0M0F3V3ZEdnJZNUNxV1BiQ1N4SWdGcVRaRm4yNVJsNnpIQkdYZThOOVM0MzlrL0k1TTJieDVqeHJiS3lvNjZJa0d3VE5ySVJLbkE9PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlDTlRDQ0FaNmdBd0lCQWdJRVMzNDNnakFOQmdrcWhraUc5dzBCQVFVRkFEQlZNUXN3Q1FZRFZRUUdFd0pWVXpFTE1Ba0dBMVVFQ0F3Q1EwRXhGakFVQmdOVkJBY01EVTF2ZFc1MFlXbHVJRlpwWlhjeERUQUxCZ05WQkFvTUJGZFRUekl4RWpBUUJnTlZCQU1NQ1d4dlkyRnNhRzl6ZERBZUZ3MHhNREF5TVRrd056QXlNalphRncwek5UQXlNVE13TnpBeU1qWmFNRlV4Q3pBSkJnTlZCQVlUQWxWVE1Rc3dDUVlEVlFRSURBSkRRVEVXTUJRR0ExVUVCd3dOVFc5MWJuUmhhVzRnVm1sbGR6RU5NQXNHQTFVRUNnd0VWMU5QTWpFU01CQUdBMVVFQXd3SmJHOWpZV3hvYjNOME1JR2ZNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRQ1VwL29WMXZXYzgvVGtRU2lBdlRvdXNNek9NNGFzQjJpbHRyMlFLb3puaTVhVkZ1ODE4TXBPTFpJcjhMTW5UeldsbEp2dmFBNVJBQWRwYkVDYis0OEZqYkJlMGhzZVVkTjVIcHd2bkgvRFc4WmNjR3ZrNTNJNk9ycTdoTEN2MVpIdHVPQ29rZ2h6L0FUcmh5UHErUWt0TWZYblJTNEhyS0dKVHp4YUNjVTdPUUlEQVFBQm94SXdFREFPQmdOVkhROEJBZjhFQkFNQ0JQQXdEUVlKS29aSWh2Y05BUUVGQlFBRGdZRUFXNXdQUjdjcjFMQWRxK0lyUjQ0aVFsUkc1SVRDWlhZOWhJMFB5Z0xQMnJIQU5oK1BZZlRteGJ1T255a05HeWhNNkZqRkxiVzJ1WkhRVFkxak1yUHByak9ybXlLNXNqSlJPNGQxRGVHSFQvWW5JanM5Sm9nUkt2NFhIRUN3THRJVmRBYklkV0hFdFZaSnlNU2t0Y3l5c0ZjdnVoUFFLOFFjL0UvV3E4dUhTQ289PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWwycDpOYW1lSURQb2xpY3kgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIEFsbG93Q3JlYXRlPSJ0cnVlIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNpc3RlbnQiIFNQTmFtZVF1YWxpZmllcj0iSXNzdWVyIi8+PHNhbWwycDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIENvbXBhcmlzb249ImV4YWN0Ij48c2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZiB4bWxuczpzYW1sPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpQYXNzd29yZFByb3RlY3RlZFRyYW5zcG9ydDwvc2FtbDpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwycDpSZXF1ZXN0ZWRBdXRobkNvbnRleHQ+PC9zYW1scDpBdXRoblJlcXVlc3Q+";

    public static final String HOST_NAME = "localhost";
    public static final int PORT = 8080;
    public static final String GATEWAY_ENDPOINT = "http://" + HOST_NAME + ":" + PORT + "/gateway";
    public static final String SAMPLE_PROTOCOL = "sampleProtocol";
    public static final String RELAY_STATE = "RelayState";
    public static final String EXTERNAL_IDP = "externalIDP";
    public static final String ASSERTION = "Assertion";
    public static final String QUERY_PARAM_SEPARATOR = "&";
    public static final String AUTHENTICATED_USER = "authenticatedUser";
    public static final String AUTHENTICATED_USER_NAME = "ExternalAuthenticatedUser";
    public static final String RESPONSE_CONTEXT = "/response";
    public static final String SAMPLE_SP_NAME = "sample";
    public static final String SAMPLE_ISSUER_NAME = "travelocity.com";
    public static final String SAMPLE_IDP_NAME = "myidp";
    public static final String SAML_REQUEST_PARAM = "SAMLRequest";
    public static final String SP_ENTITY_ID = "spEntityID";

    public static final String authnRequestPage = "<html>\n" +
            "\t<body>\n" +
            "        \t<p>You are now redirected to $url \n" +
            "        \tIf the redirection fails, please click the post button.</p>\n" +
            "\n" +
            "        \t<form method='post' action='$url'>\n" +
            "       \t\t\t<p>\n" +
            "                    <!--$params-->\n" +
            "        \t\t\t<button type='submit'>POST</button>\n" +
            "       \t\t\t</p>\n" +
            "       \t\t</form>\n" +
            "       \t\t<script type='text/javascript'>\n" +
            "        \t\tdocument.forms[0].submit();\n" +
            "        \t</script>\n" +
            "        </body>\n" +
            "</html>";

}

