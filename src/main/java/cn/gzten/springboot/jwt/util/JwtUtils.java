package cn.gzten.springboot.jwt.util;

import cn.gzten.springboot.jwt.dto.JwtDto;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;

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

public class JwtUtils {
    private Algorithm algorithmForEncryption;
    private Algorithm algorithmForDecrypt;
    static final long EXPIRY_SECONDS = 300;

    public JwtUtils(String privateKeyBase64,
                    String keystorePass,
                    String keyAlias,
                    String publicKeyBase64) throws JWTCreationException {
        try {
            var ins = new ByteArrayInputStream(Base64.getDecoder().decode(privateKeyBase64));
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

    public String encrypt(String claim, String jti, long expiresIn) {
        String token = JWT.create()
                .withExpiresAt(new Date(System.currentTimeMillis() + expiresIn * 1000))
                .withClaim("claimsInComma", claim)
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
        try {
            JWTVerifier verifier = JWT.require(algorithmForDecrypt)
                    .build(); //Reusable verifier instance
            verifier.verify(token);
            return true;
        } catch (JWTVerificationException e){
            e.printStackTrace();
            return false;
        }
    }

}
