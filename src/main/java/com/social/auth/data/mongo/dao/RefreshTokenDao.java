package com.social.auth.data.mongo.dao;

import com.social.auth.data.mongo.models.RefreshToken;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.bson.Document;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.convert.MongoConverter;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;


@Log4j2
@Component
@AllArgsConstructor
public class RefreshTokenDao {

    private final RefreshTokenRepository refreshTokenRepository;

    private final MongoTemplate mongoTemplate;

    private final MongoConverter mongoConverter;


    public List<RefreshToken> findByIdIn(List<String> chunk) {
        return refreshTokenRepository.findByIdIn(chunk);
    }

    public void deleteAll(List<RefreshToken> auths) {
        refreshTokenRepository.deleteAll(auths);
    }

    public void insertAllIgnoreAuditing(List<RefreshToken> refreshTokens) {
        List<Document> documents = refreshTokens.stream().map(refreshToken -> {
            Document updateDoc = new Document();
            mongoConverter.write(refreshToken,  updateDoc);
            return updateDoc;
        }).collect(Collectors.toList());

        mongoTemplate.getCollection("refresh_token").insertMany(documents);
    }

    public List<RefreshToken> findByAuthIdIn(List<String> chunk) {
        return refreshTokenRepository.findByAuthIdIn(chunk);
    }

    public void deleteByAuthIdIn(List<String> chunk) {
        refreshTokenRepository.deleteByAuthIdIn(chunk);
    }
}
