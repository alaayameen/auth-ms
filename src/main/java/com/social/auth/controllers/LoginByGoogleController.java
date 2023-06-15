package com.social.auth.controllers;

import com.social.auth.data.mongo.dao.AuthDao;
import com.social.auth.data.mongo.dao.DeviceInfoDao;
import com.social.auth.data.mongo.models.Auth;
import com.social.auth.data.mongo.models.DeviceInfo;
import com.social.auth.data.mongo.models.LoginTypeEnum;
import com.social.auth.gateway.UserApiClient;
import com.social.auth.services.GoogleService;
import com.social.auth.services.RefreshTokenService;
import com.social.auth.services.models.SocialMediaUserInfo;
import com.social.auth.utils.AuthUtils;
import com.social.swagger.called.user.model.AddNewUserRequest;
import com.social.swagger.called.user.model.AddNewUserRespond;
import com.social.swagger.model.auth.AuthenticateRespond;
import com.social.swagger.model.auth.LoginByGoogleRequest;
import com.social.core.models.RuleEnum;
import com.social.core.models.UsedLoginEnum;
import com.social.core.models.UserInfo;
import com.social.core.utils.JWTUtil;
import com.social.swagger.called.user.model.UpdateUserRequest;
import com.social.swagger.called.user.model.UserInfoForAdmin;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
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
public class LoginByGoogleController {
    private JWTUtil jwtUtil;
    private AuthDao authDao;
    AuthUtils authUtils;
    private UserApiClient userApiClient;
    private final RefreshTokenService refreshTokenService;
    private PasswordEncoder passwordEncoder;
    private GoogleService googleService;
    private DeviceInfoDao deviceInfoDao;
    
    public AuthenticateRespond loginByGoogle(LoginByGoogleRequest loginByGoogleRequest, String acceptLanguage) {
        log.debug("loginByGoogle called with GoogleToken{}", loginByGoogleRequest);
        String googleToken = loginByGoogleRequest.getGoogleToken(); // Get Google token
        SocialMediaUserInfo socialMediaUserInfo = googleService.verifyAndGetUserInfo(googleToken);
        log.debug("googleService.verifyAndGetUserInfo {} , response: {}", socialMediaUserInfo, googleToken);

        AuthenticateRespond authenticateRespond = new AuthenticateRespond();
        Auth authData = authDao.getAuthDataByEmail(socialMediaUserInfo.getEmail());
        String adminToken = "Bearer " + jwtUtil.generateTokenForAdminUser();
        UserInfoForAdmin userInfoForAdmin = null;
        
        log.debug("loginByGoogle authData {}", authData);
        if (authData == null) {
            AddNewUserRespond addNewUserRespond = callUserApiToAddNewUser(socialMediaUserInfo, generateTokenFromGoogleUSerInfo(socialMediaUserInfo.getEmail(), null, acceptLanguage,RuleEnum.NORMAL, userInfoForAdmin), RuleEnum.NORMAL);
            authData = storeAuthInDB(loginByGoogleRequest, socialMediaUserInfo, addNewUserRespond.getUserId());
            log.debug("loginByGoogle add new user {} authData {}", addNewUserRespond ,authData);
        } else {
            userInfoForAdmin = userApiClient.getUserStatusDetailByAdmin(adminToken, authData.getUserId());
            log.debug("loginByGoogle userInfo {}", userInfoForAdmin);
            if (userInfoForAdmin != null) {
                if (Boolean.TRUE.equals(userInfoForAdmin.isIsDeleted())) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "DELETED_USER");
                }

                if (Boolean.FALSE.equals(userInfoForAdmin.isActive())) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "USER_IS_DEACTIVATED");
                }

                if (Boolean.TRUE.equals(userInfoForAdmin.isMarkedForDelete())) {
                    if (Boolean.TRUE.equals(loginByGoogleRequest.isRestoreAccount())) {
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
//            callUserApiToUpdateUser(socialMediaUserInfo, generateTokenFromGoogleUSerInfo(socialMediaUserInfo.getEmail(), authData.getUserId(), acceptLanguage, RuleEnum.NORMAL, userInfoForAdmin), RuleEnum.NORMAL);
        }
        authenticateRespond.setAccessToken(generateTokenFromGoogleUSerInfo(authData.getEmail(), authData.getUserId(), acceptLanguage,authData.getRule(), userInfoForAdmin));
        authenticateRespond.setRefreshToken(refreshTokenService.createRefreshToken(authData.getId()).getToken());
        log.debug("loginByGoogle tokens are generated {}", authenticateRespond);
        return authenticateRespond;
    }

    private void callUserApiToUpdateUser(SocialMediaUserInfo socialMediaUserInfo, String accessToken, RuleEnum rule) {
        UpdateUserRequest updateUserRequest = mapSocialMediaUserInfoToUpdateUserRequest(socialMediaUserInfo, rule);
        userApiClient.updateUser("Bearer " + accessToken, updateUserRequest);
    }

    private UpdateUserRequest mapSocialMediaUserInfoToUpdateUserRequest(SocialMediaUserInfo socialMediaUserInfo, RuleEnum rule) {
        UpdateUserRequest updateUserRequest = new UpdateUserRequest();

        if(!StringUtils.isEmpty(socialMediaUserInfo.getName())) {
            updateUserRequest.setUserName(socialMediaUserInfo.getName());
        }
        if(!StringUtils.isEmpty(socialMediaUserInfo.getPicture())) {
            updateUserRequest.setProfilePictureUrl(socialMediaUserInfo.getPicture());
        }

        updateUserRequest.setRule(rule.getValue());

        return updateUserRequest;
    }
    private String generateTokenFromGoogleUSerInfo(String email, String userId, String acceptLanguage, RuleEnum ruleEnum, UserInfoForAdmin userInfoForAdmin) {
        UserInfo userInfo = new UserInfo();
        userInfo.setEmail(email);
        userInfo.setId(userId);
        userInfo.setUsedLoginEnum(UsedLoginEnum.EMAIL);
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

    private AddNewUserRespond callUserApiToAddNewUser(SocialMediaUserInfo socialMediaUserInfo, String accessToken,
			RuleEnum ruleEnum) {
		AddNewUserRequest addNewUserRequest = mapGoogleUserInfoToAddNewUserRequest(socialMediaUserInfo, ruleEnum);
        DeviceInfo deviceInfo = null;
		addNewUserRequest = authUtils.validateAndUpdateBirthdate(addNewUserRequest, deviceInfo);
		AddNewUserRespond respond = userApiClient.addNewUser("Bearer " + accessToken, addNewUserRequest);
		deviceInfo = authUtils.updateDeviceInfo(deviceInfo, respond);
	    deviceInfoDao.saveDeviceInfo(deviceInfo);
	       
		return respond;
	}

    private AddNewUserRequest mapGoogleUserInfoToAddNewUserRequest(SocialMediaUserInfo socialMediaUserInfo, RuleEnum rule) {
        AddNewUserRequest addNewUserRequest = new AddNewUserRequest();
        addNewUserRequest.setUserName(socialMediaUserInfo.getName());
        addNewUserRequest.setProfilePictureUrl(socialMediaUserInfo.getPicture());
        addNewUserRequest.setRule(rule.getValue());
     
        return addNewUserRequest;
    }

    private Auth storeAuthInDB(LoginByGoogleRequest loginByGoogleRequest, SocialMediaUserInfo socialMediaUserInfo, String userId) {
        Auth auth = new Auth();
        auth.setUserId(userId);
        auth.setEmail(socialMediaUserInfo.getEmail());
        auth.setLoginType(LoginTypeEnum.GOOGLE);
        auth.setPassword(passwordEncoder.encode(loginByGoogleRequest.getGoogleToken()));
        Date createdTime = Date.from(OffsetDateTime.now(ZoneOffset.UTC).toInstant());
        auth.setRegistrationTime(createdTime);
        auth.setRule(RuleEnum.NORMAL);
        return authDao.insertAuthData(auth);
    }
}
