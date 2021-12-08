package cn.gzten.jwt.service;

import cn.gzten.jwt.dto.JwtDto;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {
    private Algorithm algorithmForEncryption;
    private Algorithm algorithmForDecrypt;
    static final long EXPIRY_SECONDS = 60 * 24 * 7L;

    @Value("${jwt.public-key-base64}")
    String publicKeyBase64;
    @Value("${jwt.keystore.base64}")
    String privateKeystoreBase64;
    @Value("${jwt.keystore.passcode}")
    String keystorePass;
    @Value("${jwt.keystore.alias}")
    String keyAlias;

    @PostConstruct
    public void init() {
        try {
            var ins = new ByteArrayInputStream(Base64.getDecoder().decode(privateKeystoreBase64));
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(ins, keystorePass.toCharArray());
            Key key = keyStore.getKey(keyAlias, keystorePass.toCharArray());
            byte[] keyBytes = key.getEncoded();

            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance(key.getAlgorithm());
            algorithmForEncryption = Algorithm.RSA256(null, (RSAPrivateKey) kf.generatePrivate(keySpec));

            /**
             * Prepare the public key
             */
            keyBytes = Base64.getDecoder().decode(publicKeyBase64);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(keyBytes));
            algorithmForDecrypt = Algorithm.RSA256((RSAPublicKey) cert.getPublicKey(), null);
        } catch (IOException|UnrecoverableKeyException|InvalidKeySpecException|CertificateException|KeyStoreException|NoSuchAlgorithmException e) {
            throw new JWTCreationException("Error in JwtUtils", e);
        }
    }

    public JwtService(String privateKeystoreBase64, String publicKeyBase64, String keyAlias, String keystorePass) throws JWTCreationException {
        this();
        this.privateKeystoreBase64 = privateKeystoreBase64;
        this.publicKeyBase64 = publicKeyBase64;
        this.keyAlias = keyAlias;
        this.keystorePass = keystorePass;
        init();
    }

    /**
     * You gotta keep this, otherwise will fail
     */
    public JwtService() {}

    public String encrypt(String claim, String jti, long expiresIn) {
        String token = JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + expiresIn * 1000))
                .withClaim("claimsInJson", claim)
                .withJWTId(jti)
                .sign(algorithmForEncryption);

        return token;
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
