package com.social.auth.data.mongo.models;
import com.social.core.models.UsedLoginEnum;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDate;
import java.util.Date;


@Document(collection = "user")
@Data
@CompoundIndexes({
        @CompoundIndex(name = "email_mobileNumber",
                def = "{'email' : 1, 'mobileNumber': 1}", unique = true)
})
public class User {
    @Id
    private String id;
    @Indexed
    private String email;
    @Indexed
    private String mobileNumber;
    @Indexed
    private String userName;
    @Indexed
    private String country;
    private UsedLoginEnum usedLoginEnum;

    private LocalDate birthDate;
    private String password;
    private String firstName;
    private String lastName;
    private String role;
    private String profileImageUrl;

    private Date creationTime;
    private Date lastUpdateTime;


}