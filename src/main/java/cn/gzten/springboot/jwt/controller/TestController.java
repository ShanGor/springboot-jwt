package cn.gzten.springboot.jwt.controller;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@RestController
public class TestController {
    private WebClient webClient = WebClient.create("http://localhost:8080");
    public static final ParameterizedTypeReference<Map<String, String>> TYPE_MAP_S_S = new ParameterizedTypeReference<>() {};

    @GetMapping("/test/1")
    public Map<String, String> api1() {
        var res = new HashMap<String, String>();
        res.put("hello", "world");
        return res;
    }
    @GetMapping("/test/2")
    public Map<String, String> api2() {
        var res = new HashMap<String, String>();
        res.put("hey", "hey you you");
        return res;
    }

    @GetMapping("/test")
    public Mono<Map<String, String>> api() {
        return webClient.get().uri("/test/2")
                .exchangeToMono(r -> r.bodyToMono(TYPE_MAP_S_S))
                .zipWith(webClient.get().uri("/test/1")
                        .exchangeToMono(r -> r.bodyToMono(TYPE_MAP_S_S)))
                .map(tuple -> {
                    var r1 = tuple.getT1();
                    var r2 = tuple.getT2();
                    r1.putAll(r2);
                    return r1;
                })
        ;
    }
}
