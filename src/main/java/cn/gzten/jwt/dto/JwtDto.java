package cn.gzten.jwt.dto;

import cn.gzten.util.JsonUtil;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * `
 * {
 *   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsidGVzdGp3dHJlc291cmNlaWQiXSwidXNlcl9uYW1lIjoiYWRtaW4uYWRtaW4iLCJzY29wZSI6WyJyZWFkIiwid3JpdGUiXSwiZXhwIjoxNDk0NDU0MjgyLCJhdXRob3JpdGllcyI6WyJTVEFOREFSRF9VU0VSIiwiQURNSU5fVVNFUiJdLCJqdGkiOiIwYmQ4ZTQ1MC03ZjVjLTQ5ZjMtOTFmMC01Nzc1YjdiY2MwMGYiLCJjbGllbnRfaWQiOiJ0ZXN0and0Y2xpZW50aWQifQ.rvEAa4dIz8hT8uxzfjkEJKG982Ree5PdUW17KtFyeec",
 *   "token_type": "bearer",
 *   "expires_in": 43199,
 *   "scope": "read write",
 *   "jti": "0bd8e450-7f5c-49f3-91f0-5775b7bcc00f"
 * }`
 */
public record JwtDto(@JsonProperty("access_token") String accessToken,
                     @JsonProperty("token_type") String tokenType,
                     @JsonProperty("expires_in") long expiresIn,
                     String scope,
                     String jti) {
    @Override
    public String toString() {
        try {
            return JsonUtil.toString(this);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
