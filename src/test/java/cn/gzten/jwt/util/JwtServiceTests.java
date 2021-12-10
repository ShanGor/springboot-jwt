package cn.gzten.jwt.util;

import cn.gzten.jwt.service.JwtService;
import cn.gzten.util.JsonUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
public class JwtServiceTests {
    /**
     * Test the RSA256
     */
    @Test
    public void testEncryptAndDecryptWithRSA256() throws JsonProcessingException {
        String publicKeyBase64 = "MIIDSzCCAjOgAwIBAgIELvW1rDANBgkqhkiG9w0BAQsFADBWMQswCQYDVQQGEwJISzEMMAoGA1UECBMDVEtPMQwwCgYDVQQHEwNUS08xKzApBgNVBAMTIkNvbnN1bWVyIE9VPVByaXZhdGUgQmFua2luZyBPPUhTQkMwHhcNMTgwODA4MTMxMTE4WhcNMTgxMTA2MTMxMTE4WjBWMQswCQYDVQQGEwJISzEMMAoGA1UECBMDVEtPMQwwCgYDVQQHEwNUS08xKzApBgNVBAMTIkNvbnN1bWVyIE9VPVByaXZhdGUgQmFua2luZyBPPUhTQkMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKDUA1UQ3gl24q8Lz3LuubvjoqTvUfXXbnQH0dXTiZw4KefM9O8ocXukkNdCjFJYDlEhbjM3rXduhB1ZDuCfsxCU12i6qkD2NEBl45bbgtL0wcay6bFNcl/stbZVZt1tqWQJ8aEDv9zfZaUgTseNmNcdr0Z29sN2zno8pxn/rRgC41ZUtyjcqMjsl2VdbqaFD72OueGk5Rr1ZEHTC5oJsYCPjX0H5xmidBYSn6lPyBjwvVj4ZaufN7QTY8lLe47u9TWNhml5a9mzD3SmLWkkTtSsvy2ADCPXeATKjUoh87mIdtqqVQ1axunWDvqO8MHj1z1jTLsu5QGQ1HwEfsLUttAgMBAAGjITAfMB0GA1UdDgQWBBSz/Lz7dXxFpwB6onuqPGeSYlOzeDANBgkqhkiG9w0BAQsFAAOCAQEAPMfMuQG/0pvt3qJNMy7dNYaokH6GY1P+zmhNOtEXlDy+oFi9xLcNKyFOLnVd2oEplt1nkR5b29VeJNEjlDv4I7ckjjt+8p5wkab5msyJM74tXNh6l85BaFwXG9DQ9tG3Nl72R+RTxYolreTLQV6S2Mv0i9Wfc3FNWpqOPXs2bODiAUFm+itDDcOsn5h+BZYShxvyMQ9McEFExbZwgkl1FIjg6eDZ4QyVh0Hkdg6gfcr9bPRAjYFUdzj4zM2g6hVJH31i4v5D/i8H0WQh8w2yWzyTmk0jz3/r++olCfHTb6n0KSwX1Y7j3x9UqDflURwAoRJKYufOXNUPUO/JMRW9Rg==";
        String privateKeystoreBase64 = "/u3+7QAAAAIAAAABAAAAAQAKbXlfdGVzdF9jYQAAAWUZqcpeAAAFAjCCBP4wDgYKKwYBBAEqAhEBAQUABIIE6vbGxb1LMX4ZXTAO4qU+IuafeZiztD2pM4Y35OmgAto6xsxuq+6Mbdj7KeUyBf6rTtCNf9UDZQFH3lwarDHWn/OnG0ndrAa4gm98msGceIsRA/wvw8q/TZ9/BOhbqaZepmfHhuYjpE828u5pdZQjfRd7YBEZ+C17vEktf19agZ7AJCi8AH7TKepLwJtK7z/Lm7XpL66ubqw5vo+4usVN58+C7WNyTro/m5OuBGgMMkPNafVbkpF8L/D5vhLUSdSPhG/n0PXe9jPOeA1PLl0ybgi8/27PWyjD0j8xWzjOuN7MFnoJCf+j+hpHs2btatoh9ZdpTbwZdIFKIlcV80RzyOZOuKsYGsOqqH98i7MII0/Gm3yZRuBVPtqS59tAdKnZTkSevM+TWYdesXqbOaOfGCerXjcPcsWYT+k86v6gakYh2THFYRzLERzCmWPRccZ4/gpU0kkAdihUVgY+klGfMYyvPN0UJkfHGJLvN2Gr4XvNSUEgN6MyeTsV06zvwrnIRNI5BQDaBC73EOjwd9Un0vlldn7D49AM5PRvTZlKRvkoxkJUotVTojkf5iBiw56bWqZSyvEYxXki+EVImbsA7KTdpPstCINgTFCYIhgs4u9ZEIV+yeZs2v1hpOIwQj6NXo945Wn59+d3/iD2ZUQWt/wwj5yQR0RRWShFOFO72s5to9CYxFFRdEW0y6K9Ecayn3FQfptUCnUN/+nNboTTMHzZqqlzce9F6pujtWRKvbD0mgscPJGXJpzG6j7+JR9FKliqvn637ULjKmsEyz+EWsksod+VXPZWpMkWz5XKGed58L1frnU4spfUDZPAjr7hZhZCJjvz0E/iGTWaQ73OBn3dMddC5bdVWssYvmYxgL7pGHijSnDd4JitNtcYEVPPgvoTlm1r0viXJmp6Iwl2ZcmEu8P+sir9AJaU+NCKWXy+BK+cVN0gXKOOf/WMhD2sk9HpXpOaQphH9G/RQV02MUuIUVGOIHW7ZdUit/U4zSp7D4+TFwNuQtTfPlwCkGm1IANT/SmQdb+6mqvppf4+anzJ0B/DxTJAB2uv8ugaGU+drC+QmZ8mPGbx8zPM0B+IJI7CG3pSZq5z0748L4PIEPZvUZNiqZ9VZ2Xf5ht/OBpjY1EjUJuqIcwfNTUlW77+n2GHzQPq0Y/qsrdfzQ12d6wDRJUV8UZEK++o/Xx4PALFVaHsSFT//jZZPD2JlF2wtCHDP3vWSd2eEPDNtb107PvZhppuxzAHrUG7oHnRk4EWCz+5RG3AmUWa8amb0DdHJnrnth1deMkv3y6Oc43bT7xF1YGMnmktH5EkyTX0VSNXwvxwccQZWqD/4yzztPySNh2Hr8QPLADvZFjgg3aGzSCxf5UBxB5yMGqibpXC0Kz+6zFY+m6GFb3aeeXAn3I098C1K9cASSDtfYDGxktqjsFauwGX4N61qyuQ6gEaNfsBIKdUW3NXTbYMhKA8jjKCwdvdxl3v3ZWJuhjgLTdsN+80zgSoXWrerjrC9UA0VRDsBipVmAo8SWVNF9k386nPmUFVCDZ8Zh8V1wP7g2PBY/UvkYuS6CbjaSaRQCMAzNt4sqiZqlFUeb87Bxlzz5bZDWt96RacRHxtkJB3ikD+CT95Oz1Jka/sujpqv1R7TxkIQ8gq1axiEEU1Pj+U/TPYImqEzLixSOCV2dcAAAABAAVYLjUwOQAAA08wggNLMIICM6ADAgECAgQu9bWsMA0GCSqGSIb3DQEBCwUAMFYxCzAJBgNVBAYTAkhLMQwwCgYDVQQIEwNUS08xDDAKBgNVBAcTA1RLTzErMCkGA1UEAxMiQ29uc3VtZXIgT1U9UHJpdmF0ZSBCYW5raW5nIE89SFNCQzAeFw0xODA4MDgxMzExMThaFw0xODExMDYxMzExMThaMFYxCzAJBgNVBAYTAkhLMQwwCgYDVQQIEwNUS08xDDAKBgNVBAcTA1RLTzErMCkGA1UEAxMiQ29uc3VtZXIgT1U9UHJpdmF0ZSBCYW5raW5nIE89SFNCQzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMoNQDVRDeCXbirwvPcu65u+OipO9R9ddudAfR1dOJnDgp58z07yhxe6SQ10KMUlgOUSFuMzetd26EHVkO4J+zEJTXaLqqQPY0QGXjltuC0vTBxrLpsU1yX+y1tlVm3W2pZAnxoQO/3N9lpSBOx42Y1x2vRnb2w3bOejynGf+tGALjVlS3KNyoyOyXZV1upoUPvY654aTlGvVkQdMLmgmxgI+NfQfnGaJ0FhKfqU/IGPC9WPhlq583tBNjyUt7ju71NY2GaXlr2bMPdKYtaSRO1Ky/LYAMI9d4BMqNSiHzuYh22qpVDVrG6dYO+o7wwePXPWNMuy7lAZDUfAR+wtS20CAwEAAaMhMB8wHQYDVR0OBBYEFLP8vPt1fEWnAHqie6o8Z5JiU7N4MA0GCSqGSIb3DQEBCwUAA4IBAQA8x8y5Ab/Sm+3eok0zLt01hqiQfoZjU/7OaE060ReUPL6gWL3Etw0rIU4udV3agSmW3WeRHlvb1V4k0SOUO/gjtySOO37ynnCRpvmazIkzvi1c2HqXzkFoXBcb0ND20bc2XvZH5FPFiiWt5MtBXpLYy/SL1Z9zcU1amo49ezZs4OIBQWb6K0MNw6yfmH4FlhKHG/IxD0xwQUTFtnCCSXUUiODp4NnhDJWHQeR2DqB9yv1s9ECNgVR3OPjMzaDqFUkffWLi/kP+LwfRZCHzDbJbPJOaTSPPf+v76iUJ8dNvqfQpLBfVjuPfH1SoN+VRHAChEkpi585c1Q9Q78kxFb1GqzvyXgPn8h0UBN8BUU/UsMz0L14=";
        String keystorePass = "changeit";
        String keyAlias = "my_test_ca";

        var jwtUtils = new JwtService();
        ReflectionTestUtils.setField(jwtUtils, "privateKeystoreBase64", privateKeystoreBase64);
        ReflectionTestUtils.setField(jwtUtils, "publicKeyBase64", publicKeyBase64);
        ReflectionTestUtils.setField(jwtUtils, "keyAlias", keyAlias);
        ReflectionTestUtils.setField(jwtUtils, "keystorePass", keystorePass);
        ReflectionTestUtils.setField(jwtUtils, "algorithm", "RSA256");
        jwtUtils.init();
        var token = jwtUtils.encrypt();
        log.info(token);
        assertTrue(jwtUtils.isValid(token));

        var jwt = jwtUtils.encrypt("Hello");
        log.info(JsonUtil.toString(jwt));
        assertTrue(jwtUtils.isValid(jwt.accessToken()));

    }

    /**
     * Test the ECDSA256
     */
    @Test
    public void testEncryptAndDecryptECDSA256() throws JsonProcessingException {
        var publicKeyBase64 = "MIIBlzCCATugAwIBAgIEZ7gxujAMBggqhkjOPQQDAgUAMEAxCzAJBgNVBAYTAkNOMQswCQYDVQQKEwJHWjERMA8GA1UECxMIZ3p0ZW4uY24xETAPBgNVBAMTCGd6dGVuLmNuMB4XDTIxMTIxMDAyMjYyNloXDTQxMTIwNTAyMjYyNlowQDELMAkGA1UEBhMCQ04xCzAJBgNVBAoTAkdaMREwDwYDVQQLEwhnenRlbi5jbjERMA8GA1UEAxMIZ3p0ZW4uY24wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASaOnFVmn4021V/J1n+6vo3r+wDQ6AStF9fMT8zyI0ffmgsEnc4xubuzEMRMKvL7b7KqHdKImafalLcV3FhJkhBoyEwHzAdBgNVHQ4EFgQUlYBxHSAwIHYjTemRp88tWnTrNqEwDAYIKoZIzj0EAwIFAANIADBFAiEAh0cwj517rY6F6RHjdg9FjP20Ss1zcJQqsja2VPiKdZ0CIBpQcUBX2/K75MmeEFp7R+y3Qu0sdbiz8B4m2fyJskbt";
        var privateKeystoreBase64 = "MIIDqAIBAzCCA2EGCSqGSIb3DQEHAaCCA1IEggNOMIIDSjCB3wYJKoZIhvcNAQcBoIHRBIHOMIHLMIHIBgsqhkiG9w0BDAoBAqB3MHUwKQYKKoZIhvcNAQwBAzAbBBSV/Nx1fgosGhWXBugLESeHYIHxKgIDAMNQBEgwBIFS7sS7XvEO8rTbx88b8MVLUjeQcx258SdgBIPRk7uGsNzp3aFVrcym0/gI/HdikVDlDe4BewWcHHeVFvvr7Pnvf+DFHo0xQDAbBgkqhkiG9w0BCRQxDh4MAG0AeQBfAGsAZQB5MCEGCSqGSIb3DQEJFTEUBBJUaW1lIDE2MzkxMDMxODY1OTAwggJkBgkqhkiG9w0BBwagggJVMIICUQIBADCCAkoGCSqGSIb3DQEHATApBgoqhkiG9w0BDAEGMBsEFPmlxd4+rV2EY+5jtuEyWwBgcmXGAgMAw1CAggIQyOsbiLepf1G3pHZXTamRBvr+gY5bWZrU/SG4rdojb95uVP6IbHlE8y7qHNlCOYcf1CsN+1+iInl3SMZ4NM2hnU5YnSvaAuW5dt0Y+KXENh3avcTfOpwLkzn+bfSUZxs9ejKql401t+df75TR2qhkymZl6s9Z8WkHH9Y7uQ1tfRr90mziZ7GjHtkVVSGCx3N522xbYO+LEKUA+OTcXn4Rsptv5l7UP0gZL+CyYD0DjrHFEZWwUxX6iShJd7G+99mYvVWxF1HMl1otczFRPSMM93Eac/RQ1Ppat6UO0mUrauXbOKIbug095ehTEbI4ub+6Iy1IxZXgfMPamYZgOYijCRkC9JMpdGrQIsRkMDA+8ULy+9HdhPbZ4lMReisXb/zHvs8PE0QLEYUEEQkV1T9V7tFZENWK8EPRynR4y4x18PgFPNruf7qAOlIH2/fMNcC4kgEhs3P1qfej4DDAfBD6etcbtmhHrGZLlxKcPsOIrQ41AAJtetwCewIZPp0eYbDG/rx9fkoU6osbyy4Rups2xuJJ9CFWmaeFz57YPUQFwjEuaIBsyXmWWK3mE3ZTi7932AKew371Zfs24hbEnFVI7iWB4zvUQNatsMag+i7FA4DbMOo2pDAIgW4oQiYBbqfg8n/jv8lauRz9VumIuHoNxuGwZG5bOYKEvJOr8DD4x9r3u9ZQ4rbEndTA54BcaY92MD4wITAJBgUrDgMCGgUABBToyesUaQpM70Fu0xwVUsnZOr4AzwQUlkPcpXffOVe6m7Y1ZmVCaNV++hUCAwGGoA==";
        var keystorePass = "changeit";
        var keyAlias = "my_key";

        var jwtUtils = new JwtService();
        ReflectionTestUtils.setField(jwtUtils, "privateKeystoreBase64", privateKeystoreBase64);
        ReflectionTestUtils.setField(jwtUtils, "publicKeyBase64", publicKeyBase64);
        ReflectionTestUtils.setField(jwtUtils, "keyAlias", keyAlias);
        ReflectionTestUtils.setField(jwtUtils, "keystorePass", keystorePass);
        ReflectionTestUtils.setField(jwtUtils, "algorithm", "ECDSA256");
        jwtUtils.init();
        var token = jwtUtils.encrypt();
        log.info(token);
        assertTrue(jwtUtils.isValid(token));

        var jwt = jwtUtils.encrypt("Hello");
        log.info(JsonUtil.toString(jwt));
        assertTrue(jwtUtils.isValid(jwt.accessToken()));
    }

    /**
     * Test the HMAC256
     */
    @Test
    public void testEncryptAndDecryptHMAC256() throws JsonProcessingException {
        var hmacKeyBase64 = "aGVsbG8gd29ybGQK";

        var jwtUtils = new JwtService();
        ReflectionTestUtils.setField(jwtUtils, "hmacKeyBase64", hmacKeyBase64);
        ReflectionTestUtils.setField(jwtUtils, "algorithm", "HMAC256");
        jwtUtils.init();
        var token = jwtUtils.encrypt();
        log.info(token);
        assertTrue(jwtUtils.isValid(token));

        var jwt = jwtUtils.encrypt("Hello");
        log.info(JsonUtil.toString(jwt));
        assertTrue(jwtUtils.isValid(jwt.accessToken()));
    }
}
