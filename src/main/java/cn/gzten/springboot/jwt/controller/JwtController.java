package cn.gzten.springboot.jwt.controller;

import cn.gzten.springboot.jwt.domain.User;
import cn.gzten.springboot.jwt.dto.JwtDto;
import cn.gzten.springboot.jwt.repository.UserRepository;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Locale;

@RestController
public class JwtController {
    private UserRepository userRepo;

    @PostMapping("/oauth/token")
    public JwtDto generateJwt(@RequestParam("grant_type") String grantType,
                              @RequestParam("username") String username,
                              @RequestParam("password") String password) {
        if (grantType == null || !grantType.toLowerCase(Locale.ROOT).equals("password")) {
            throw new JWTCreationException("Unknown grant_type provided: " + grantType, new Exception());
        }
        User user = userRepo.findByUsername(username);

        var token = "";
        var expiresIn = 1L;

        return new JwtDto(token, "bearer", expiresIn, "read write", "");
    }

    @Autowired
    public void setUserRepo(UserRepository userRepo) {
        this.userRepo = userRepo;
    }
}
