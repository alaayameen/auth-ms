package com.social.auth.controllers;

import com.social.auth.data.mongo.dao.AuthDao;
import com.social.auth.data.mongo.models.Auth;
import com.social.auth.data.mongo.models.LoginTypeEnum;
import com.social.auth.data.mongo.models.RefreshToken;
import com.social.auth.gateway.UserApiClient;
import com.social.auth.services.RefreshTokenService;
import com.social.auth.services.exception.TokenRefreshException;
import com.social.swagger.called.user.model.UserInfoForAdmin;
import com.social.swagger.model.auth.RefreshTokenRequest;
import com.social.swagger.model.auth.RefreshTokenRespond;
import com.social.core.models.UsedLoginEnum;
import com.social.core.models.UserInfo;
import com.social.core.utils.JWTUtil;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Controller;


@Log4j2
@Controller
@AllArgsConstructor
public class RefreshTokenController {
    private final RefreshTokenService refreshTokenService;
    private AuthDao authDao;
    private JWTUtil jwtUtil;
    
    UserApiClient userApiClient;
    
    
    public RefreshTokenRespond refreshToken(RefreshTokenRequest refreshTokenRequest, String acceptLanguage){
    	
        return refreshTokenService.findByToken(refreshTokenRequest.getRefreshToken())
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getAuthId)
                .map(authId -> {
                    Auth authData = authDao.getAuthDataByAuthId(authId);
                    UserInfo userInfo = new UserInfo();
                    userInfo.setId(authData.getUserId());
                    
                    String adminToken = "Bearer " + jwtUtil.generateTokenForAdminUser();
                    UserInfoForAdmin userInfoForAdmin = userApiClient.getUserStatusDetailByAdmin(adminToken, authData.getUserId());
                    log.debug("refresh token userInfo {}", userInfoForAdmin);
                    userInfo.setIsActive(userInfoForAdmin.isActive());
                    userInfo.setIsDeleted(userInfoForAdmin.isIsDeleted());
                    userInfo.setNumericUserId(userInfoForAdmin.getNumericUserId());
                    userInfo.setUserName(userInfoForAdmin.getUserName());

                    if(authData.getLoginType().equals(LoginTypeEnum.MOBILE)){
                        userInfo.setUsedLoginEnum(UsedLoginEnum.MOBILE);
                    }else if(authData.getLoginType().equals(LoginTypeEnum.APPLE)) {
                    	userInfo.setUsedLoginEnum(UsedLoginEnum.APPLE);
                    	
                    }else if(authData.getLoginType().equals(LoginTypeEnum.FACEBOOK)) {
                    	userInfo.setUsedLoginEnum(UsedLoginEnum.FACEBOOK);
                    	
                    }else if(authData.getLoginType().equals(LoginTypeEnum.GOOGLE)) {
                    	userInfo.setUsedLoginEnum(UsedLoginEnum.GOOGLE);
                    	
                    }else{
                        userInfo.setUsedLoginEnum(UsedLoginEnum.EMAIL);
                    }
                    userInfo.setMobileNumber(authData.getMobileNumber());
                    userInfo.setEmail(authData.getEmail());
                    if(acceptLanguage != null && !"".equals(acceptLanguage)) {
                    }
                    userInfo.setRule(authData.getRule());

                    String token = jwtUtil.generateTokenFromUserInfo(userInfo);
                    RefreshTokenRespond refreshTokenRespond = new RefreshTokenRespond();
                    refreshTokenRespond.setRefreshToken(refreshTokenRequest.getRefreshToken());
                    refreshTokenRespond.setAccessToken(token);
                    return refreshTokenRespond;
                })
                .orElseThrow(() -> new TokenRefreshException(refreshTokenRequest.getRefreshToken(),
                        "Refresh token is not in database!"));
    }
}
