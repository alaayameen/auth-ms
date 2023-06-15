package com.social.auth.data.mongo.dao;

import com.social.auth.data.mongo.models.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {
    Optional<RefreshToken> findByToken(String token);
    void deleteByAuthId(List<String> authIds);

    List<RefreshToken> findByIdIn(List<String> chunk);

    List<RefreshToken> findByAuthIdIn(List<String> chunk);

    void deleteByAuthIdIn(List<String> chunk);
}