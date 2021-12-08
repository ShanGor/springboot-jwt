package cn.gzten.jwt.dto;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.LinkedList;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JwtPayloadTest {
    @Test
    public void testSerialize() {
        String username = "samuel";
        var l = new LinkedList<GrantedAuthority>();
        l.add((GrantedAuthority) () -> "ADMIN");
        l.add((GrantedAuthority) () -> "NORMAL");

        var str = new JwtPayload("1", username, l).toString();
        assertEquals("{\"username\":\"samuel\",\"id\":\"1\",\"roles\":[\"ADMIN\",\"NORMAL\"]}", str);
    }

    @Test
    public void testDeserialize() throws JsonProcessingException {
        var str = "{\"username\":\"samuel\",\"roles\":[\"ADMIN\",\"NORMAL\"]}";
        var payload = JwtPayload.fromJson(str);
        assertEquals("samuel", payload.getUsername());
        assertEquals(2, payload.getRoles().size());
    }

    @Test
    public void testFromToken() {
        var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJjbGFpbXNJbkpzb24iOiJ7XCJ1c2VybmFtZVwiOlwiam9obi5kb2VcIixcInJvbGVzXCI6W1wiU1RBTkRBUkRfVVNFUlwiXX0iLCJleHAiOjE2Mzg4Njk4MjMsImp0aSI6ImEyZGMxZGRiLWI4ZTQtNDA2Ny1hOWE0LTRiMjYzMzQzNGRlOSJ9.fnlEEd_05h5Rr6c2jAxLFVFKHJfZov7-KUEeizkX3zU3TYlEK8c2VDvMpSNZVe0l6TPrpQ-04HI4Y-47ecxfSyZJx2juUkiPbpjq_MetideRnlBLakR0gFe0jj-1F-nx9AoTzFoRdWvObFY9vQXPRWgfYX_0i_48OgLAk6d6AWeFXeEg7AS5lvK_Qy4bPNbcwXmV-5Fl3CEZb9cWMJNFdLekfPPeEzwlOZSy2MspTx3tNrPizWxUbvj0yxzGm76Cm87u7gfJzrZmj1UW99HXUoOrOyGLVUP0lVmHOvz9laOg6tga8vnRHr5tDkBWTbc82Zb8774zLwMK3jhD25Xg2A";
        var payload = JwtPayload.fromToken(token);
        assertEquals("john.doe", payload.getUsername());
        assertEquals(1, payload.getRoles().size());
    }
}
