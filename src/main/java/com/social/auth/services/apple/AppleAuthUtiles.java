package com.social.auth.services.apple;

import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.*;
import java.security.PrivateKey;
import java.util.Date;

@Component
@Log4j2
public class AppleAuthUtiles {

    @Autowired
    static ResourceLoader resourceLoader;

    private final static String appleKeyId = "8KQZ7B789U";
    private final static String appleTeamId = "LSQH8WFPX6";



    public String generateJWT(String identifierFromApp) throws Exception {
        // Generate a private key for token verification from your end with your creds
        PrivateKey pKey = generatePrivateKey();

        String token = Jwts.builder()
                .setHeaderParam(JwsHeader.KEY_ID, appleKeyId)
                .setIssuer(appleTeamId)
                .setAudience("https://appleid.apple.com")
                .setSubject(identifierFromApp)
                .setExpiration(new Date(System.currentTimeMillis() + (1000 * 60 * 5)))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .signWith(pKey, SignatureAlgorithm.ES256)
                .compact();
        return token;
    }

    // Method to generate private key from certificate you created
    private static PrivateKey generatePrivateKey(){
        // here i have added cert at resource/apple folder. So if you have added somewhere else, just replace it with your path ofcert
        PrivateKey pKey = null;
        try {
            final PEMParser pemParser = new PEMParser(new BufferedReader(new InputStreamReader(new ClassPathResource("apple/cert.p8").getInputStream())));
            final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            final PrivateKeyInfo object = (PrivateKeyInfo) pemParser.readObject();
             pKey = converter.getPrivateKey(object);
            pemParser.close();
        }catch (Exception e){
            e.printStackTrace();
            log.error("failed on generatePrivateKey with error:", e);
        }

        return pKey;
    }
}
