package com.social.auth.controllers;

import com.social.auth.data.mongo.dao.DeviceInfoDao;
import com.social.auth.data.mongo.models.LoginTypeEnum;
import com.social.auth.gateway.UserApiClient;
import com.social.auth.services.RefreshTokenService;
import com.social.auth.services.models.SocialMediaUserInfo;
import com.social.swagger.model.auth.AuthenticateRespond;
import com.social.auth.data.mongo.dao.AuthDao;
import com.social.auth.data.mongo.models.Auth;
import com.social.auth.data.mongo.models.DeviceInfo;
import com.social.auth.services.FaceBookService;
import com.social.auth.utils.AuthUtils;
import com.social.core.models.RuleEnum;
import com.social.core.models.UsedLoginEnum;
import com.social.core.models.UserInfo;
import com.social.core.utils.JWTUtil;
import com.social.swagger.called.user.model.AddNewUserRequest;
import com.social.swagger.called.user.model.AddNewUserRespond;
import com.social.swagger.called.user.model.UpdateUserRequest;
import com.social.swagger.called.user.model.UserInfoForAdmin;
import com.social.swagger.model.auth.LoginByFacebookRequest;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;


@Log4j2
@Controller
@AllArgsConstructor
public class LoginByFacebookController {
	private static final String BEARER = "Bearer ";
    private JWTUtil jwtUtil;
    private AuthDao authDao;
    AuthUtils authUtils;
    private UserApiClient userApiClient;
    @Autowired
    private FaceBookService faceBookService;
    private final RefreshTokenService refreshTokenService;
    private PasswordEncoder passwordEncoder;
    private DeviceInfoDao deviceInfoDao;
    
    public AuthenticateRespond loginByFacebook(LoginByFacebookRequest loginByFacebookRequest, String acceptLanguage) {
        log.info("loginByFacebook called with FacebookToken{}", loginByFacebookRequest);
        String faceBooktoken = loginByFacebookRequest.getFacebookToken();
        SocialMediaUserInfo socialMediaUserInfo = faceBookService.verifyAndGetUserInfo(faceBooktoken);
        log.info("faceBookService.verifyAndGetUserInfo called with token {} , response: {}", faceBooktoken, socialMediaUserInfo);

        AuthenticateRespond authenticateRespond = new AuthenticateRespond();
        Auth authData = authDao.findBySocialUserIdAndLoginType(socialMediaUserInfo.getId(), LoginTypeEnum.FACEBOOK.name());

        if (authData == null && socialMediaUserInfo.getEmail() != null) {
            /*
            If user registered by email for old data
             */
            authData = authDao.getAuthDataByEmail(socialMediaUserInfo.getEmail());
        }

        String adminToken = "Bearer " + jwtUtil.generateTokenForAdminUser();
        UserInfoForAdmin userInfoForAdmin = null;
        
        log.info("loginByFacebook social info {} authData {}", socialMediaUserInfo, authData);
        
        if (authData == null)  {
        	log.info("loginByFacebook social info {} authData null ", socialMediaUserInfo);
            AddNewUserRespond addNewUserRespond = callUserApiToAddNewUser(
                    socialMediaUserInfo, generateTokenFromSocialMediaUserInfo(socialMediaUserInfo.getEmail(), null, acceptLanguage,RuleEnum.NORMAL, userInfoForAdmin),
                    RuleEnum.NORMAL);
            log.info("loginByFacebook social info {} authData null addNewUserRespond {}", socialMediaUserInfo, addNewUserRespond);
            authData = storeAuthInDB(loginByFacebookRequest, socialMediaUserInfo, addNewUserRespond.getUserId());
            log.info("loginByFacebook addNewUserRespond {} authData {}", addNewUserRespond, authData);
        } else {
        	log.info("loginByFacebook social info {} authData not null: {}", socialMediaUserInfo, authData);
            userInfoForAdmin = userApiClient.getUserStatusDetailByAdmin(adminToken, authData.getUserId());
            log.info("loginByFacebook userInfo {}", userInfoForAdmin);
            
            if (userInfoForAdmin != null) {
                if (Boolean.TRUE.equals(userInfoForAdmin.isIsDeleted())) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "DELETED_USER");
                }

                if (Boolean.FALSE.equals(userInfoForAdmin.isActive())) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "USER_IS_DEACTIVATED");
                }

                if (Boolean.TRUE.equals(userInfoForAdmin.isMarkedForDelete())) {
                    if (Boolean.TRUE.equals(loginByFacebookRequest.isRestoreAccount())) {
                        if ( userInfoForAdmin.getCanRollbackDeleteDate() != null && LocalDate.now().isBefore(userInfoForAdmin.getCanRollbackDeleteDate())) {
                            userInfoForAdmin.setMarkedForDelete(false);
                            userApiClient.rollbackUserDeleteStatus(adminToken, authData.getUserId());
                        } else {
                            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "CANNOT_RESTORE_DELETED_ACCOUNT");
                        }
                    } else {
                        if ( userInfoForAdmin.getCanRollbackDeleteDate() != null && LocalDate.now().isBefore(userInfoForAdmin.getCanRollbackDeleteDate())) {
                            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ACCOUNT_MARKED_FOR_DELETE");
                        } else {
                            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ACCOUNT_IS_DELETED");
                        }
                    }
                }
            }
//            callUserApiToUpdateUser(socialMediaUserInfo, generateTokenFromSocialMediaUserInfo(socialMediaUserInfo.getEmail(), authData.getUserId(), acceptLanguage, RuleEnum.NORMAL, userInfoForAdmin), RuleEnum.NORMAL);
        }
        authenticateRespond.setAccessToken(generateTokenFromSocialMediaUserInfo(authData.getEmail(), authData.getUserId(), acceptLanguage, authData.getRule(), userInfoForAdmin));
        authenticateRespond.setRefreshToken(refreshTokenService.createRefreshToken(authData.getId()).getToken());
        log.info("loginByFacebook tokens are generated {}", authenticateRespond);
        
        return authenticateRespond;
    }

    private void callUserApiToUpdateUser(SocialMediaUserInfo socialMediaUserInfo, String accessToken, RuleEnum rule) {
        UpdateUserRequest updateUserRequest = mapSocialMediaUserInfoToUpdateUserRequest(socialMediaUserInfo, rule);
        userApiClient.updateUser("Bearer " + accessToken, updateUserRequest);
    }

    private UpdateUserRequest mapSocialMediaUserInfoToUpdateUserRequest(SocialMediaUserInfo socialMediaUserInfo, RuleEnum ruleEnum) {
        UpdateUserRequest updateUserRequest = new UpdateUserRequest();
        String firstName = "";
        String lastName = "";

        if(!StringUtils.isEmpty(socialMediaUserInfo.getFirstName())) {
            firstName = socialMediaUserInfo.getFirstName();
        }
        if(!StringUtils.isEmpty(socialMediaUserInfo.getLastName())) {
            lastName = socialMediaUserInfo.getLastName();
        }
        if(!StringUtils.isEmpty(firstName) || !StringUtils.isEmpty(lastName)) {
            updateUserRequest.setUserName(firstName.concat(" ").concat(lastName).trim());
        }
        if(!StringUtils.isEmpty(socialMediaUserInfo.getPicture())) {
            updateUserRequest.setProfilePictureUrl(socialMediaUserInfo.getPicture());
        }

        updateUserRequest.setRule(ruleEnum.getValue());

        return updateUserRequest;
    }

    private SocialMediaUserInfo mapFacebookUserToSocialMediaUserInfo(JSONObject jsonObject) throws JSONException {
        SocialMediaUserInfo socialMediaUserInfo = new SocialMediaUserInfo();
        socialMediaUserInfo.setEmail(jsonObject.getString("email"));
        socialMediaUserInfo.setPicture(jsonObject.getJSONObject("picture").getJSONObject("data").getString("url"));
        return socialMediaUserInfo;
    }

    private AddNewUserRespond callUserApiToAddNewUser(SocialMediaUserInfo socialMediaUserInfo, String accessToken, RuleEnum rule) {
        AddNewUserRequest addNewUserRequest = mapRegisterByMobileRequestToAddNewUserRequest(socialMediaUserInfo, rule);
        DeviceInfo deviceInfo = null;
		
        addNewUserRequest = authUtils.validateAndUpdateBirthdate(addNewUserRequest, deviceInfo);
        AddNewUserRespond respond = userApiClient.addNewUser(BEARER + accessToken, addNewUserRequest);
        deviceInfo = authUtils.updateDeviceInfo(deviceInfo, respond);
        deviceInfoDao.saveDeviceInfo(deviceInfo);
		        
        return respond;
    }

    private AddNewUserRequest   mapRegisterByMobileRequestToAddNewUserRequest(SocialMediaUserInfo socialMediaUserInfo, RuleEnum rule) {
        AddNewUserRequest addNewUserRequest = new AddNewUserRequest();

        String firstName = "";
        String lastName = "";

        if(!StringUtils.isEmpty(socialMediaUserInfo.getFirstName())) {
            firstName = socialMediaUserInfo.getFirstName();
        }
        if(!StringUtils.isEmpty(socialMediaUserInfo.getLastName())) {
            lastName = socialMediaUserInfo.getLastName();
        }
        if(!StringUtils.isEmpty(firstName) || !StringUtils.isEmpty(lastName)) {
            addNewUserRequest.setUserName(firstName.concat(" ").concat(lastName).trim());
        }

        addNewUserRequest.setProfilePictureUrl(socialMediaUserInfo.getPicture());

        addNewUserRequest.setRule(rule.getValue());
        
        return addNewUserRequest;
    }

    private String generateTokenFromSocialMediaUserInfo(String email, String userId, String acceptLanguage, RuleEnum ruleEnum, UserInfoForAdmin userInfoForAdmin) {
    	log.info("loginByFacebook generateTokenFromSocialMediaUserInfo email {}, userId {}, rule {}, userInfo {}",email, userId, ruleEnum, userInfoForAdmin );
        UserInfo userInfo;
        userInfo = new UserInfo();
        userInfo.setId(userId);
        userInfo.setEmail(email);
        userInfo.setUsedLoginEnum(UsedLoginEnum.FACEBOOK);
        userInfo.setRule(ruleEnum);

        if (userInfoForAdmin != null) {
            userInfo.setIsActive(userInfoForAdmin.isActive());
            userInfo.setIsDeleted(userInfoForAdmin.isMarkedForDelete());
            userInfo.setUserName(userInfoForAdmin.getUserName());
            userInfo.setNumericUserId(userInfoForAdmin.getNumericUserId());
        }

        if(acceptLanguage != null && !"".equals(acceptLanguage)) {
        }
        return jwtUtil.generateTokenFromUserInfo(userInfo);
    }

    private Auth storeAuthInDB(LoginByFacebookRequest loginByFacebookRequest, SocialMediaUserInfo socialMediaUserInfo, String userId) {
        Auth auth = new Auth();
        auth.setUserId(userId);
        auth.setSocialUserId(socialMediaUserInfo.getId());
        auth.setEmail(socialMediaUserInfo.getEmail());
        auth.setLoginType(LoginTypeEnum.FACEBOOK);
        auth.setPassword(passwordEncoder.encode(loginByFacebookRequest.getFacebookToken()));
        Date createdTime = Date.from(OffsetDateTime.now(ZoneOffset.UTC).toInstant());
        auth.setRegistrationTime(createdTime);
        auth.setRule(RuleEnum.NORMAL);
        return authDao.insertAuthData(auth);
    }
}
