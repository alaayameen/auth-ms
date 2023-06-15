package com.social.auth.data.mongo.dao;

import com.social.auth.data.mongo.models.Auth;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AuthRepository extends MongoRepository<Auth, String> {
    Auth findByMobileNumber(String mobileNumber);

    Auth findByEmail(String email);

    List<Auth> findByUserId(String userId);

    Auth findRuleByUserId(String userId);

    List<Auth> findRuleByUserIdIn(List<String> userIds);

    void deleteByUserId(String userId);

    Auth findBySocialUserIdAndLoginType(String userId, String loginType);

    List<Auth> findByIdIn(List<String> chunk);

    void deleteByIdIn(List<String> chunk);
    
    Auth findByMobileNumberAndLoginType(String mobile, String loginType);
    
    Auth findByEmailAndLoginType(String email, String loginType);
    
}