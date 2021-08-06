package cn.gzten.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonUtil {
    private static final ThreadLocal<ObjectMapper> om = ThreadLocal.withInitial(() -> {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return objectMapper;
    });

    public static final ObjectMapper getObjectMapper() {
        return om.get();
    }

    public static final String toString(Object o) throws JsonProcessingException {
        return getObjectMapper().writeValueAsString(o);
    }
}
