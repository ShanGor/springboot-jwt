package cn.gzten.jwt.dto;

import cn.gzten.util.JsonUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import org.junit.jupiter.api.Test;

import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JwtDtoTests {
    private static final Logger log = Logger.getLogger(JwtDtoTests.class.getName());
    @Test
    public void testIt() {
        var o = new JwtDto("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJleHAiOjE2MjgyNTM2Mzl9.uNj9HAqLrut8t8Rlc0dNLOCvZBuqkyLR-XrZtwQnzRUJjBojeQeLoJKnkUas5jugR0gCIQvYhhG68MmxT9FsjXbfp7z7HjoGoeIzI9tG6RDjU2yIgAkH4UD3KJFmHlT4_0zZLJnmGU5ZZaKsKEjhGyaB6IyZawFy2FWqL1fXyyrJtV-FWLmBK17AMcuOUWOya-GOIZZvdSLRe3pUPHtwb1o37BR90Iq3lq1r3pAV0JR8J5zsVKstjHI8zzGD_8ZgPct5rONX19pu3mT-_6WU5BCrQjtsOOd38_i03MPbB4ziJ1mageMmNtupOAnOlQoDML7GGy_0yXyu4-5Q7ZC5zg", "bearer", 2548796L,"read write", "0bd8e450-7f5c-49f3-91f0-5775b7bcc00f");
        try {
            String str = o.toString();
            var o1 = JsonUtil.getObjectMapper().readValue(str, JwtDto.class);
            assertEquals(o.accessToken(), o1.accessToken());
            assertEquals(o.expiresIn(), o1.expiresIn());
            assertEquals(o.scope(), o1.scope());
            assertEquals(o.tokenType(), o1.tokenType());
            assertEquals(o.jti(), o1.jti());
            log.info(str);
        } catch (RuntimeException e) {
            e.printStackTrace();
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
    }
}
