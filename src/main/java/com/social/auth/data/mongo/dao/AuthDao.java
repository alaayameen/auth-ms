package com.social.auth.data.mongo.dao;

import com.social.auth.data.mongo.models.LoginTypeEnum;
import com.social.auth.data.mongo.models.Auth;
import com.social.core.models.UsedLoginEnum;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.bson.Document;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.UncategorizedMongoDbException;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.convert.MongoConverter;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.data.mongodb.core.index.PartialIndexFilter;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.schema.JsonSchemaObject;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;


@Log4j2
@Component
@AllArgsConstructor
public class AuthDao {

    private static final String SOCIAL_USER_ID = "socialUserId";

    private final AuthRepository authRepository;

    private final MongoTemplate mongoTemplate;

    private final MongoConverter mongoConverter;

    public Auth insertAuthData(Auth authData) {
        try {
 	
            Auth auth = null;
            if(authData.getLoginType() == LoginTypeEnum.MOBILE) {
            	
            	auth = authRepository.findByMobileNumberAndLoginType(authData.getMobileNumber(), authData.getLoginType().name());
            } else if(authData.getLoginType() == LoginTypeEnum.EMAIL) {

            	auth = authRepository.findByEmailAndLoginType(authData.getEmail(), authData.getLoginType().name());
            } 
            else {
            	auth = authRepository.findBySocialUserIdAndLoginType(authData.getSocialUserId(), authData.getLoginType().name());
            }
            		
            
            if (auth != null) {
                log.error("Social user id: {} already exist with type: {}", authData.getSocialUserId(), authData.getLoginType().name());
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "SOCIAL_ID_EXIST");
            }
            return authRepository.insert(authData);
        } catch (UncategorizedMongoDbException e) {
            log.error("MONGO_DB_CONNECTION_FAILED", e);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "MONGO_DB_CONNECTION_FAILED");

        }
    }
    public Auth getAuthDataByMobileNumber(String mobileNumber) {
        return authRepository.findByMobileNumber(mobileNumber);
    }
    public Auth getAuthDataByEmail(String email) {
        return authRepository.findByEmail(email);
    }
    
    public Auth findBySocialUserIdAndLoginType(String userId, String loginType) {
        return authRepository.findBySocialUserIdAndLoginType(userId, loginType);
    }
    public Auth getAuthDataByAuthId(String authId) {
        return authRepository.findById(authId).get();
    }

    public void update(Auth auth) {
        authRepository.save(auth);
    }

    @PostConstruct
    private void initIndex() {

        Index mobileNumberPartialIndex = new Index()
                .background()
                .unique()
                .named("mobile_number_unique_partial_index")
                .on("mobileNumber", Sort.Direction.ASC)
                .partial(PartialIndexFilter.of(
                        Criteria.where("loginType")
                                .is(UsedLoginEnum.MOBILE.name())));

        mongoTemplate.indexOps("auth").ensureIndex(mobileNumberPartialIndex);
    }

    @PostConstruct
    private void socialUserIdFacebook() {

        Index mobileNumberPartialIndex = new Index()
                .background()
                .unique()
                .named("facebook_social_user_id_unique_partial_index")
                .on(SOCIAL_USER_ID, Sort.Direction.ASC)
                .partial(PartialIndexFilter.of(
                        Criteria.where("loginType")
                                .is(UsedLoginEnum.FACEBOOK.name()).and(SOCIAL_USER_ID).type(JsonSchemaObject.Type.STRING)));

        mongoTemplate.indexOps("auth").ensureIndex(mobileNumberPartialIndex);
    }

    @PostConstruct
    private void socialUserIdGoogle() {

        Index mobileNumberPartialIndex = new Index()
                .background()
                .unique()
                .named("google_social_user_id_unique_partial_index")
                .on(SOCIAL_USER_ID, Sort.Direction.ASC)
                .partial(PartialIndexFilter.of(
                        Criteria.where("loginType")
                                .is(UsedLoginEnum.GOOGLE.name()).and(SOCIAL_USER_ID).type(JsonSchemaObject.Type.STRING)));

        mongoTemplate.indexOps("auth").ensureIndex(mobileNumberPartialIndex);
    }

    @PostConstruct
    private void socialUserIdApple() {

        Index mobileNumberPartialIndex = new Index()
                .background()
                .unique()
                .named("apple_social_user_id_unique_partial_index")
                .on(SOCIAL_USER_ID, Sort.Direction.ASC)
                .partial(PartialIndexFilter.of(
                        Criteria.where("loginType")
                                .is(UsedLoginEnum.APPLE.name()).and(SOCIAL_USER_ID).type(JsonSchemaObject.Type.STRING)));

        mongoTemplate.indexOps("auth").ensureIndex(mobileNumberPartialIndex);
    }

    public List<String> findIdByUserId(String id) {
        return authRepository.findByUserId(id).stream().map(Auth::getId).collect(Collectors.toList());
    }

    public Auth getByUserId(String id) {
    	List<Auth> authList = authRepository.findByUserId(id);
    	if(Objects.nonNull(authList)) {
    		return authList.get(0);
    	}
        return null;
    }
    
    public List<Auth> findByIdIn(List<String> chunk) {
        return authRepository.findByIdIn(chunk);
    }

    public void deleteAll(List<Auth> auths) {
        authRepository.deleteAll(auths);
    }

    public void insertAllIgnoreAuditing(List<Auth> auths) {
        List<Document> documents = auths.stream().map(post -> {
            Document updateDoc = new Document();
            mongoConverter.write(post,  updateDoc);
            return updateDoc;
        }).collect(Collectors.toList());

        mongoTemplate.getCollection("auth").insertMany(documents);
    }

    public void deleteByIdIn(List<String> chunk) {
        authRepository.deleteByIdIn(chunk);
    }
}
