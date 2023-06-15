package com.social.auth.services.apple;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.social.auth.services.models.AppleIDTokenPayload;
import com.social.auth.services.models.SocialParametersDTO;
import com.social.auth.services.models.TokenResponse;
import io.jsonwebtoken.io.Decoders;
import lombok.extern.log4j.Log4j2;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Log4j2
@Service
public class AppleAuthorizeService {

    @Autowired
    private AppleAuthUtiles appleAuthUtiles;

    private static String APPLE_AUTH_URL = "https://appleid.apple.com/auth/token";

    public AppleIDTokenPayload authorizeApple(SocialParametersDTO socialParametersDTO) throws Exception {
        log.debug("Get Apple User Profile {}", socialParametersDTO);
        String appClientId = "com.social.auth";
        //socialParametersDTO.getIdentifierFromApp();

        // generate personal verification token
        String token = appleAuthUtiles.generateJWT(appClientId);

        log.debug("Apple login appClientId {} Token {} ", appClientId, token);
        ////////// Get OAuth Token from Apple by exchanging code
        // Prepare client, you can use other Rest client library also
        OkHttpClient okHttpClient = new OkHttpClient()
                .newBuilder()
                .connectTimeout(70, TimeUnit.SECONDS)
                .writeTimeout(70, TimeUnit.SECONDS)
                .readTimeout(70, TimeUnit.SECONDS)
                .build();
        // Request body for sending parameters as FormUrl Encoded
        RequestBody requestBody = new FormBody
                .Builder()
                .add("client_id", appClientId)
                .add("client_secret", token)
                .add("grant_type", "authorization_code")
                .add("code", socialParametersDTO.getAuthorizationCode())
                .build();

        log.debug("Apple: Request body {}", requestBody.toString());
        
        // Prepare rest request
        Request request = new Request
                .Builder()
                .url(APPLE_AUTH_URL)
                .post(requestBody)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .build();

        // Execute api call and get Response
        Response resp = okHttpClient.newCall(request).execute();
        String response = resp.body().string();
        
        log.debug("Apple: Response {} ", response);
        // Parse response as DTO
        ObjectMapper objectMapper = new ObjectMapper();
        TokenResponse tokenResponse = objectMapper.readValue(response, TokenResponse.class);
        
        log.debug("Apple: Token response {}", tokenResponse);
        
        // Parse id token from Token
        String idToken = tokenResponse.getId_token();
        String payload = idToken.split("\\.")[1];// 0 is header we ignore it for now
        String decoded = new String(Decoders.BASE64.decode(payload));
        log.debug("payload", payload);
        AppleIDTokenPayload idTokenPayload = new Gson().fromJson(decoded, AppleIDTokenPayload.class);
        log.debug("idTokenPayload", idTokenPayload);

        return idTokenPayload;
//        User user = new User();
//        if (idTokenPayload != null ) {
//            JSONObject _user = new JSONObject(String.valueOf(idTokenPayload));
//            JSONObject name = _user != null &&_user.has("name") ? _user.getJSONObject("name") : null;
//            String firstName = name.getString("firstName");
//            String lastName = name.getString("lastName");
//            String email = _user.has("email") ? _user.getString("email") : null;
//            user.setEmail(email);
//            user.setFirstName(firstName);
//            user.setLastName(lastName);
//        }
//        return user;
    }
}
