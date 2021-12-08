package cn.gzten.jwt.exception;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

public class MyAccessDeniedHandler implements ServerAccessDeniedHandler {
    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        var resp = exchange.getResponse();
        resp.setRawStatusCode(403);

        var mono = ReactiveSecurityContextHolder.getContext().map(ctx -> {
            var aut = ctx.getAuthentication();
            if (aut.isAuthenticated()) {
                return resp.bufferFactory().wrap("User is not authorized to this operation!".getBytes());
            } else {
                return resp.bufferFactory().wrap(aut.getDetails()
                        .toString().getBytes(StandardCharsets.UTF_8));
            }

        });
        return resp.writeAndFlushWith(Mono.just(mono));
    }
}
