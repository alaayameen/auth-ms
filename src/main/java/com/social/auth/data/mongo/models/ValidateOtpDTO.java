package com.social.auth.data.mongo.models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Document(collection = "validate_otp")
@Data
public class ValidateOtpDTO {
    @Id
    private String id;

    @Indexed()
    private String mobileNumber;

    private String otpNumber;

    private Integer numberOfRetries;

    private Instant lastUpdateTime;
    
    private String email;
}
