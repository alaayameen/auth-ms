package com.social.auth.data.mongo.models;

import com.social.core.models.RuleEnum;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Document(collection = "auth")
@Data
@CompoundIndexes({
        @CompoundIndex(name = "social_user_login_type",
                def = "{'socialUserId' : 1, 'loginType': 1}")
})
public class Auth {
    @Id
    private String id;
    @Indexed
    private String email;
    
    private String mobileNumber;
    @Indexed
    private String userId;
    private LoginTypeEnum loginType;
    private Date registrationTime;
    @Indexed
    private RuleEnum rule;
    private String password;
    private String socialUserId;
}
