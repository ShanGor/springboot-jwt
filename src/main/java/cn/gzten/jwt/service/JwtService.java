package cn.gzten.jwt.service;

import cn.gzten.jwt.dto.JwtDto;
import cn.gzten.jwt.exception.AppException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Service
@Slf4j
public class JwtService {
    private Algorithm algorithmForEncryption;
    private Algorithm algorithmForDecrypt;

    static final long EXPIRY_SECONDS = 60 * 24 * 7L;

    @Value("${jwt.algorithm:RSA256}")
    String algorithm;
    @Value("${jwt.hmac-key-base64:aGVsbG8gd29ybGQK}")
    String hmacKeyBase64;

    @Value("${jwt.public-key-base64:}")
    String publicKeyBase64;
    @Value("${jwt.keystore.base64:}")
    String privateKeystoreBase64;
    @Value("${jwt.keystore.passcode:}")
    String keystorePass;
    @Value("${jwt.keystore.alias:}")
    String keyAlias;

    @PostConstruct
    public void init() {
        if ("HMAC256".equals(algorithm)) {
            initHMAC();
        } else {
            initAsymmetric();
        }
    }

    public void initHMAC() {
        try {
            algorithmForEncryption = Algorithm.HMAC256(Base64.getDecoder().decode(hmacKeyBase64));
            algorithmForDecrypt = Algorithm.HMAC256(Base64.getDecoder().decode(hmacKeyBase64));

        } catch (Exception e) {
            throw new AppException(500, "Failed at JwtService.initSymmetric: " + e.getMessage());
        }

    }

    public void initAsymmetric() {
        try {
            var ins = new ByteArrayInputStream(Base64.getDecoder().decode(privateKeystoreBase64));
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(ins, keystorePass.toCharArray());
            Key key = keyStore.getKey(keyAlias, keystorePass.toCharArray());
            byte[] keyBytes = key.getEncoded();

            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance(key.getAlgorithm());

            /**
             * Prepare the public key
             */
            keyBytes = Base64.getDecoder().decode(publicKeyBase64);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(keyBytes));

            if ("RSA256".equals(algorithm)) {
                algorithmForEncryption = Algorithm.RSA256(null, (RSAPrivateKey) kf.generatePrivate(keySpec));
                algorithmForDecrypt = Algorithm.RSA256((RSAPublicKey) cert.getPublicKey(), null);
            } else if ("ECDSA256".equals(algorithm)) {
                algorithmForEncryption = Algorithm.ECDSA256(null, (ECPrivateKey) kf.generatePrivate(keySpec));
                algorithmForDecrypt = Algorithm.ECDSA256((ECPublicKey) cert.getPublicKey(), null);
            } else {
                throw new AppException(500, "Configuration for the `jwt.algorithm` is unknown: " + algorithm);
            }

        } catch (IOException|UnrecoverableKeyException|InvalidKeySpecException|CertificateException|KeyStoreException|NoSuchAlgorithmException e) {
            throw new JWTCreationException("Error in JwtUtils", e);
        }
    }

    public String encrypt(String claim, String jti, long expiresIn) {
        return JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + expiresIn * 1000))
                .withClaim("claimsInJson", claim)
                .withJWTId(jti)
                .sign(algorithmForEncryption);
    }

    public String encrypt() {
        return encrypt(null, UUID.randomUUID().toString(), EXPIRY_SECONDS);
    }

    public JwtDto encrypt(String claim) {
        String jti = UUID.randomUUID().toString();
        String token = encrypt(claim, jti, EXPIRY_SECONDS);
        return new JwtDto(token, "bearer", EXPIRY_SECONDS, "read write", jti);
    }

    /**
     * Check if the token is valid or not.
     * @param token
     * @return
     */
    public boolean isValid(String token) {
        JWTVerifier verifier = JWT.require(algorithmForDecrypt)
                .build(); //Reusable verifier instance
        verifier.verify(token);
        return true;
    }
}
