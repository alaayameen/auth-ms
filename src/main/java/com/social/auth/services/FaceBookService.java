package com.social.auth.services;

import com.social.auth.services.models.SocialMediaUserInfo;
import lombok.extern.log4j.Log4j2;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;

@Log4j2
@Service
public class FaceBookService {

    @Value("${faceBook.tokenUrl}")
    private String FACEBOOK_TOKEN_URL;

    @Value("${faceBook.validateTokenUrl}")
    private String FACEBOOK_VALIDATE_TOKEN_URL;

    @Value("${faceBook.facebookAppId}")
    private String FACEBOOK_APP_ID;

    public SocialMediaUserInfo verifyAndGetUserInfo(String faceBookToken) {
        log.info("verifyAndGetUserInfo called with faceBookToken{}", faceBookToken);
        RestTemplate restTemplate = new RestTemplate();
        SocialMediaUserInfo socialMediaUserInfo = null;
        String facebook = null;
        String validate = null;
        // field names which will be retrieved from facebook
        final String fields = "id,email,first_name,last_name,picture";
        try {
            UriComponentsBuilder validateUri = UriComponentsBuilder.fromUriString(FACEBOOK_VALIDATE_TOKEN_URL)
                    .queryParam("input_token", faceBookToken).queryParam("access_token", FACEBOOK_APP_ID);
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(FACEBOOK_TOKEN_URL)
                    .queryParam("access_token", faceBookToken).queryParam("fields", fields);

            log.info("Facebook profile uri {}", uriBuilder.toUriString());

            validate = restTemplate.getForObject(validateUri.toUriString(), String.class);
            JSONObject validateJsonObject = new JSONObject(validate);

            facebook = restTemplate.getForObject(uriBuilder.toUriString(), String.class);

            JSONObject jsonObject = new JSONObject(facebook);
            socialMediaUserInfo = mapFacebookUserToSocialMediaUserInfo(jsonObject);
            log.info("Facebook user authenticated and profile fetched successfully, details [{}]", facebook.toString());
            log.info("Facebook socialMediaUserInfo {}",socialMediaUserInfo);
        } catch (Exception e) {
            log.error("Not able to authenticate from Facebook");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_TOKEN");
        }
        return socialMediaUserInfo;
    }

    private SocialMediaUserInfo mapFacebookUserToSocialMediaUserInfo(JSONObject jsonObject) throws JSONException {
        SocialMediaUserInfo socialMediaUserInfo = new SocialMediaUserInfo();

        if (jsonObject.has("id")) {
            socialMediaUserInfo.setId(jsonObject.get("id").toString());
        }
        if (jsonObject.has("email")) {
            socialMediaUserInfo.setEmail(jsonObject.get("email").toString());
        }
        if (jsonObject.has("first_name")) {
            socialMediaUserInfo.setFirstName(jsonObject.get("first_name").toString());
        }
        if (jsonObject.has("last_name")) {
            socialMediaUserInfo.setLastName(jsonObject.get("last_name").toString());
        }
        if (jsonObject.has("picture")) {
            socialMediaUserInfo.setPicture(jsonObject.getJSONObject("picture").getJSONObject("data").getString("url"));
        }
        return socialMediaUserInfo;
    }
}
