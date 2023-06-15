package com.social.auth.data.mongo.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum LoginTypeEnum {
    MOBILE("MOBILE"),
    
    FACEBOOK("FACEBOOK"),

    GOOGLE("GOOGLE"),

    APPLE("APPLE"),
	
	EMAIL("EMAIL");

    private String value;

    LoginTypeEnum(String value) {
      this.value = value;
    }

    @Override
    @JsonValue
    public String toString() {
      return String.valueOf(value);
    }

    @JsonCreator
    public static LoginTypeEnum fromValue(String text) {
      for (LoginTypeEnum b : LoginTypeEnum.values()) {
        if (String.valueOf(b.value).equals(text)) {
          return b;
        }
      }
      return null;
    }
  }