package com.social.auth.services.models;

import lombok.Data;
import lombok.EqualsAndHashCode;

import java.io.Serializable;

/**
 * A DTO for the SocialUser.
 */
@Data
@EqualsAndHashCode
public class SocialParametersDTO implements Serializable {

    private static final long serialVersionUID = 3484800209656475818L;

    // code varaible returned from sign in request
    private String authorizationCode;

    // If Apple sign in authoriation sends user object as string
    private String userObj;

    // id token from Apple Sign in Authorization if asked
   // private String idToken;

    // kid or key identifier from mobile app authorization
    //private String identifierFromApp;

}