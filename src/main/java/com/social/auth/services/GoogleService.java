package com.social.auth.services;

import com.social.auth.services.models.SocialMediaUserInfo;
import com.social.auth.utils.GoogleProps;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.annotation.PostConstruct;

@Log4j2
@Service
public class GoogleService {

    @Autowired
    private GoogleProps googleProps;
    private GoogleIdTokenVerifier verifier;

    @PostConstruct
    public void init() {
        log.info("..");
        verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                .setAudience(googleProps.getAppIds())
                .build(); // Build the verifier
    }

    public SocialMediaUserInfo verifyAndGetUserInfo(String googleToken) {
        log.debug("verifyAndGetUserInfo called with googleToken{}", googleToken);
        GoogleIdToken idToken = null;
        IdToken.Payload payload = null;
        try {
            idToken = verifier.verify(googleToken);  // Verify token
            if (idToken == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_TOKEN");
            }
            payload = idToken.getPayload();
            log.info("Google user authenticated and profile fetched successfully, details [{}]", payload);
            return mapGooglePayloadToGoogleUserInfo(payload);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_TOKEN");
        }
    }

    private SocialMediaUserInfo mapGooglePayloadToGoogleUserInfo(IdToken.Payload payload) {
        String email = ((GoogleIdToken.Payload) payload).getEmail();
        String pictureUrl = (String) payload.get("picture");
        String name = (String) payload.get("name");
        SocialMediaUserInfo socialMediaUserInfo = new SocialMediaUserInfo();
        socialMediaUserInfo.setEmail(email);
        socialMediaUserInfo.setName(name);
        socialMediaUserInfo.setPicture(pictureUrl);
        return socialMediaUserInfo;
    }


}
