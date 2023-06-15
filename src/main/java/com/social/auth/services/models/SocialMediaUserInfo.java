package com.social.auth.services.models;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode
public class SocialMediaUserInfo {

    private String id;

    private String email;

    private String name;

    private String firstName;

    private String lastName;

    private String picture;
}
