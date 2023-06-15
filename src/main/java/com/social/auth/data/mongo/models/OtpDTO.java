package com.social.auth.data.mongo.models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Document(collection = "otp")
@Data
public class OtpDTO {
    @Id
    private String id;
    
    private String mobileNumber;

    private String otpNumber;

    private Instant expiryDate;

    private Integer numberOfRetries;

    private Instant lastUpdateTime;
    
    private String email;
}
