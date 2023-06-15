package com.social.auth.data.mongo.models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;


@Document(collection =  "refresh_token")
@Data
public class RefreshToken {
  @Id
  private String id;

  @Indexed
  private String authId;
  @Indexed
  private String token;

  private Instant expiryDate;

}