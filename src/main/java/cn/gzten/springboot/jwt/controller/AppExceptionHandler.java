package cn.gzten.springboot.jwt.controller;

import cn.gzten.springboot.jwt.dto.ErrorResponse;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class AppExceptionHandler {

    /**
     * Please ignore the error message in the UsernameNotFoundException, do not reply to the front end to avoid user enumeration.
     * @return
     */
    @ExceptionHandler(value = UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationErrors() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse("E001", "Username or password incorrect!"));
    }

    @ExceptionHandler
    public ResponseEntity<ErrorResponse> handleTokenGenerationErrors(JWTCreationException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse("E002", e.getMessage()));
    }
}
