package com.social.auth.controllers;

import com.social.auth.data.mongo.models.LoginTypeEnum;
import com.social.auth.data.mongo.models.User;
import com.social.auth.gateway.UserApiClient;
import com.social.auth.services.RefreshTokenService;
import com.social.auth.services.apple.AppleAuthorizeService;
import com.social.auth.services.models.AppleIDTokenPayload;
import com.social.auth.services.models.SocialMediaUserInfo;
import com.social.auth.services.models.SocialParametersDTO;
import com.social.swagger.called.user.model.AddNewUserRequest;
import com.social.swagger.called.user.model.AddNewUserRespond;
import com.social.swagger.called.user.model.UpdateUserRequest;
import com.social.swagger.called.user.model.UserInfoForAdmin;
import com.social.swagger.model.auth.AuthenticateRespond;
import com.social.swagger.model.auth.LoginByAppleRequest;
import com.social.auth.data.mongo.dao.AuthDao;
import com.social.auth.data.mongo.dao.DeviceInfoDao;
import com.social.auth.data.mongo.models.Auth;
import com.social.auth.data.mongo.models.DeviceInfo;
import com.social.auth.utils.AuthUtils;
import com.social.core.models.RuleEnum;
import com.social.core.models.UsedLoginEnum;
import com.social.core.models.UserInfo;
import com.social.core.utils.JWTUtil;
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
import java.util.Random;

@Log4j2
@Controller
@AllArgsConstructor
public class LoginByAppleController {
	private static final String BEARER = "Bearer ";
    private JWTUtil jwtUtil;
    private AuthDao authDao;
    AuthUtils authUtils;
    private UserApiClient userApiClient;
    private AppleAuthorizeService appleAuthorizeService;
    private final RefreshTokenService refreshTokenService;
    private PasswordEncoder passwordEncoder;
    private DeviceInfoDao deviceInfoDao;

    public AuthenticateRespond loginByApple(LoginByAppleRequest loginByAppleRequest, String acceptLanguage) {
        log.debug("loginByApple called with loginByAppleRequest", loginByAppleRequest);
        SocialParametersDTO socialParametersDTO = new SocialParametersDTO();
        socialParametersDTO.setAuthorizationCode(loginByAppleRequest.getAuthorizationCode());
        User user = new User();
        try {
            user = mapIdPayloadTokenToUser(appleAuthorizeService.authorizeApple(socialParametersDTO));
            log.debug("loginByApple user {}",user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        String email = user.getEmail();
        log.debug("loginByApple called with email{}", email);

        AuthenticateRespond authenticateRespond = new AuthenticateRespond();
        Auth authData = authDao.getAuthDataByEmail(email);
        String adminToken = "Bearer " + jwtUtil.generateTokenForAdminUser();
        UserInfoForAdmin userInfoForAdmin = null;
        
        log.debug("loginByApple  authData {}", authData);
        if (authData == null) {
            SocialMediaUserInfo socialMediaUserInfo = new SocialMediaUserInfo();
            if (!StringUtils.isEmpty(user.getEmail())) {
                socialMediaUserInfo.setEmail(user.getEmail());
            }
            if (!StringUtils.isEmpty(loginByAppleRequest.getFirstName())) {
                socialMediaUserInfo.setFirstName(loginByAppleRequest.getFirstName());
            }
            if (!StringUtils.isEmpty(user.getLastName())) {
                socialMediaUserInfo.setLastName(loginByAppleRequest.getLastName());
            }
            log.debug("loginByApple authData == null and social user {}", socialMediaUserInfo);
            AddNewUserRespond addNewUserRespond = callUserApiToAddNewUser(
                    socialMediaUserInfo,
                    generateTokenFromSocialMediaUserInfo(socialMediaUserInfo.getEmail(), null, acceptLanguage, RuleEnum.NORMAL, userInfoForAdmin),
                    RuleEnum.NORMAL);
            authData = storeAuthInDB(user, socialMediaUserInfo, addNewUserRespond.getUserId());
            
            log.debug("loginByApple addNewUser reponde {} authData {}", addNewUserRespond, authData);
        } else  {
            userInfoForAdmin = userApiClient.getUserStatusDetailByAdmin(adminToken, authData.getUserId());
            log.debug("loginByApple user exists userInfo {}", userInfoForAdmin);
            
            if (userInfoForAdmin != null) {
                if (Boolean.TRUE.equals(userInfoForAdmin.isIsDeleted())) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "DELETED_USER");
                }

                if (Boolean.FALSE.equals(userInfoForAdmin.isActive())) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "USER_IS_DEACTIVATED");
                }

                if (Boolean.TRUE.equals(userInfoForAdmin.isMarkedForDelete())) {
                    if (Boolean.TRUE.equals(loginByAppleRequest.isRestoreAccount())) {
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
            SocialMediaUserInfo socialMediaUserInfo = new SocialMediaUserInfo();
            if (!StringUtils.isEmpty(loginByAppleRequest.getFirstName())) {
                socialMediaUserInfo.setFirstName(loginByAppleRequest.getFirstName());
            }
            if (!StringUtils.isEmpty(loginByAppleRequest.getLastName())) {
                socialMediaUserInfo.setLastName(loginByAppleRequest.getLastName());
            }
            
            log.debug("loginByApple user exists social user {}", socialMediaUserInfo);
//            callUserApiToUpdateUser(socialMediaUserInfo, generateTokenFromSocialMediaUserInfo(socialMediaUserInfo.getEmail(), authData.getUserId(), acceptLanguage, RuleEnum.NORMAL, userInfoForAdmin), RuleEnum.NORMAL);
        }

        authenticateRespond.setAccessToken(generateTokenFromSocialMediaUserInfo(authData.getEmail(), authData.getUserId(), acceptLanguage,authData.getRule(), userInfoForAdmin));
        authenticateRespond.setRefreshToken(refreshTokenService.createRefreshToken(authData.getId()).getToken());
        
        log.debug("loginByApple tokens are generated {}", authenticateRespond);
        return authenticateRespond;
    }

    private User mapIdPayloadTokenToUser(AppleIDTokenPayload authorizeApple) {
        User user = new User();
        if(authorizeApple != null && !authorizeApple.getEmail().isEmpty()) {
            user.setEmail(authorizeApple.getEmail());
        }
        return user;
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

    private void callUserApiToUpdateUser(SocialMediaUserInfo socialMediaUserInfo, String accessToken, RuleEnum rule) {
        UpdateUserRequest updateUserRequest = mapSocialMediaUserInfoToUpdateUserRequest(socialMediaUserInfo, rule);
        userApiClient.updateUser("Bearer " + accessToken, updateUserRequest);
    }

    private AddNewUserRequest mapRegisterByMobileRequestToAddNewUserRequest(SocialMediaUserInfo socialMediaUserInfo, RuleEnum rule) {

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
        } else {
            addNewUserRequest.setUserName("user".concat(String.valueOf(new Random().nextInt(1000000000))));
        }
        if(!StringUtils.isEmpty(socialMediaUserInfo.getPicture())) {
            addNewUserRequest.setProfilePictureUrl(socialMediaUserInfo.getPicture());
        }
        addNewUserRequest.setRule(rule.getValue());
        
        return addNewUserRequest;
    }

    private UpdateUserRequest mapSocialMediaUserInfoToUpdateUserRequest(SocialMediaUserInfo socialMediaUserInfo, RuleEnum rule) {
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

        updateUserRequest.setRule(rule.getValue());

        return updateUserRequest;
    }

    private String generateTokenFromSocialMediaUserInfo(String email, String userId,String acceptLanguage, RuleEnum ruleEnum, UserInfoForAdmin userInfoForAdmin) {
        UserInfo userInfo;
        userInfo = new UserInfo();
        userInfo.setId(userId);
        userInfo.setEmail(email);
        userInfo.setUsedLoginEnum(UsedLoginEnum.EMAIL);

        if (userInfoForAdmin != null) {
            userInfo.setIsActive(userInfoForAdmin.isActive());
            userInfo.setIsDeleted(userInfoForAdmin.isMarkedForDelete());
            userInfo.setUserName(userInfoForAdmin.getUserName());
            userInfo.setNumericUserId(userInfoForAdmin.getNumericUserId());
        }

        userInfo.setRule(ruleEnum);
        if(acceptLanguage != null && !"".equals(acceptLanguage)) {
        }
        return jwtUtil.generateTokenFromUserInfo(userInfo);
    }

    private Auth storeAuthInDB(User loginByAppleRequest, SocialMediaUserInfo socialMediaUserInfo, String userId) {
        Auth auth = new Auth();
        auth.setUserId(userId);
        auth.setSocialUserId(socialMediaUserInfo.getId());
        auth.setEmail(socialMediaUserInfo.getEmail());
        auth.setLoginType(LoginTypeEnum.APPLE);
        auth.setPassword(passwordEncoder.encode(loginByAppleRequest.getEmail()));
        Date createdTime = Date.from(OffsetDateTime.now(ZoneOffset.UTC).toInstant());
        auth.setRegistrationTime(createdTime);
        auth.setRule(RuleEnum.NORMAL);
        return authDao.insertAuthData(auth);
    }
}
