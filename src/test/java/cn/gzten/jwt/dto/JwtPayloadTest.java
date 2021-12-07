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

        var str = new JwtPayload(username, l).toString();
        assertEquals("{\"username\":\"samuel\",\"roles\":[\"ADMIN\",\"NORMAL\"]}", str);
    }

    @Test
    public void testDeserialize() throws JsonProcessingException {
        var str = "{\"username\":\"samuel\",\"roles\":[\"ADMIN\",\"NORMAL\"]}";
        var payload = JwtPayload.fromJson(str);
        assertEquals("samuel", payload.getUsername());
        assertEquals(2, payload.getRoles().size());
    }
}
