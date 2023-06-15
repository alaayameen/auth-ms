package com.social.auth.controllers;
import com.social.auth.data.mongo.dao.OtpDao;
import com.social.auth.data.mongo.models.LoginTypeEnum;
import com.social.auth.data.mongo.models.OtpDTO;
import com.social.auth.gateway.UserApiClient;
import com.social.auth.services.RefreshTokenService;
import com.social.swagger.model.auth.UpdateLoginByMobilePasswordRequest;
import com.social.auth.data.mongo.dao.AuthDao;
import com.social.auth.data.mongo.dao.DeviceInfoDao;
import com.social.auth.data.mongo.models.Auth;
import com.social.auth.data.mongo.models.DeviceInfo;
import com.social.auth.utils.AuthUtils;
import com.social.core.models.RuleEnum;
import com.social.core.models.UsedLoginEnum;
import com.social.core.models.UserInfo;
import com.social.core.utils.JWTUtil;
import com.social.swagger.called.user.model.AddNewUserRequest;
import com.social.swagger.called.user.model.AddNewUserRespond;
import com.social.swagger.model.auth.AuthenticateRespond;
import com.social.swagger.model.auth.RegisterByMobileRequest;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Objects;

@Log4j2
@Controller
public class RegisterByMobileController {

    private final RefreshTokenService refreshTokenService;
    private JWTUtil jwtUtil;
    AuthUtils authUtils;
    private UserApiClient userApiClient;
    private AuthDao authDao;
    private PasswordEncoder passwordEncoder;
    private OtpDao otpDao;
    private DeviceInfoDao deviceInfoDao;
    
    public RegisterByMobileController(RefreshTokenService refreshTokenService, JWTUtil jwtUtil, UserApiClient userApiClient, AuthDao authDao, PasswordEncoder passwordEncoder, OtpDao otpDao, DeviceInfoDao deviceDao, AuthUtils authUtils) {
        this.refreshTokenService = refreshTokenService;
        this.jwtUtil = jwtUtil;
        this.userApiClient = userApiClient;
        this.authDao = authDao;
        this.passwordEncoder = passwordEncoder;
        this.otpDao = otpDao;
        this.deviceInfoDao = deviceDao;
        this.authUtils = authUtils;
    }

    @Value("${otp.validate.enabled}")
    private boolean validateOtpEnabled;

    public AuthenticateRespond execute(RegisterByMobileRequest registerByMobileRequest, String acceptLanguage, RuleEnum rule){
        log.debug("register called withcallUserApiToAddNewUser RegisterByMobileRequest{}", registerByMobileRequest);
        if(validateOtpEnabled) {
            validateOTP(registerByMobileRequest);
        }
        if(!AuthUtils.isValidPassword(registerByMobileRequest.getPassword())){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "WRONG_PASSWORD_FORMAT");
        }
        registerByMobileRequest.setMobileNumber(registerByMobileRequest.getMobileNumber().replace("+",""));
        AuthenticateRespond authenticateRespond = new AuthenticateRespond();
        authenticateRespond.setAccessToken(generateTokenFromUserInfo(registerByMobileRequest,null, acceptLanguage, rule ==null ? RuleEnum.NORMAL: rule));

        AddNewUserRespond addNewUserRespond = callUserApiToAddNewUser(registerByMobileRequest, authenticateRespond, rule ==null ? RuleEnum.NORMAL: rule);

        Auth authData = storeAuthInDB(registerByMobileRequest, addNewUserRespond.getUserId(), rule);

        authenticateRespond.setAccessToken(generateTokenFromUserInfo(registerByMobileRequest,addNewUserRespond, acceptLanguage,authData.getRule()));
        authenticateRespond.setRefreshToken(refreshTokenService.createRefreshToken(authData.getId()).getToken());
        return authenticateRespond;
    }

    public void regesterByAdmin(List<RegisterByMobileRequest> registerByAdminRequest, String rule, String acceptLanguage) {
    	log.debug("Register by admin for a list of users {}", registerByAdminRequest);
    	if(!jwtUtil.isAdminUser()) {
    		log.error("Unauthorized access exception is thrown while creating new users");
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED_ACCESS");
    	}
    	validateOtpEnabled = false;
    	for (RegisterByMobileRequest registerByMobileRequest : registerByAdminRequest) {
			log.debug("Register new user {} by admin {}", registerByAdminRequest, jwtUtil.getUserInfoFromToken());
			execute(registerByMobileRequest, acceptLanguage, RuleEnum.valueOf(rule));
			
		}
    }
    
    private void validateOTP(RegisterByMobileRequest registerByMobileRequest) {
        OtpDTO otpData = otpDao.getOtpDataByMobileNumber(registerByMobileRequest.getMobileNumber());
        if(otpData != null && otpData.getOtpNumber().equals(registerByMobileRequest.getOtpCode())){
            if(otpData.getExpiryDate().compareTo(Instant.now()) < 0) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "OTP_EXPIRED");
            }
        }else{
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "WRONG_OTP");
        }
    }

    private Auth storeAuthInDB(RegisterByMobileRequest registerByMobileRequest, String userId, RuleEnum rule) {
        Auth auth = new Auth();
        auth.setMobileNumber(registerByMobileRequest.getMobileNumber());
        auth.setUserId(userId);
        auth.setLoginType(LoginTypeEnum.MOBILE);
        auth.setPassword(passwordEncoder.encode(registerByMobileRequest.getPassword()));
        Date createdTime = Date.from(OffsetDateTime.now(ZoneOffset.UTC).toInstant());
        auth.setRegistrationTime(createdTime);
        if(RuleEnum.ADMIN.equals(rule) || 
        		RuleEnum.SYSTEM_CONTENT.equals(rule) ||
        		RuleEnum.TESTING.equals(rule)) {
        	//Double check that the user doing the action is an admin
        	if(!jwtUtil.isAdminUser()) {
        		log.error("Unauthorized access exception is thrown while creating new users");
    			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED_ACCESS");
        	}
        	auth.setRule(rule);
        }
        auth.setRule(RuleEnum.NORMAL);

        return authDao.insertAuthData(auth);
    }

    private AddNewUserRespond callUserApiToAddNewUser(RegisterByMobileRequest registerByMobileRequest, AuthenticateRespond authenticateRespond, RuleEnum rule) {
        AddNewUserRequest addNewUserRequest = mapRegisterByMobileRequestToAddNewUserRequest(registerByMobileRequest, rule);
        DeviceInfo deviceInfo = null;
        		
        addNewUserRequest = authUtils.validateAndUpdateBirthdate(addNewUserRequest, deviceInfo);
        AddNewUserRespond addNewUserRespond = userApiClient.addNewUser("Bearer " + authenticateRespond.getAccessToken(), addNewUserRequest);
        if(Objects.nonNull(deviceInfo)) {
        	deviceInfo = authUtils.updateDeviceInfo(deviceInfo, addNewUserRespond);
        	deviceInfoDao.saveDeviceInfo(deviceInfo);
        }
        return addNewUserRespond;
    }

    private String generateTokenFromUserInfo(RegisterByMobileRequest registerByMobileRequest, AddNewUserRespond userRespond, String acceptLanguage, RuleEnum ruleEnum) {
        UserInfo userInfo;
        userInfo = new UserInfo();
        
        userInfo.setMobileNumber(registerByMobileRequest.getMobileNumber());
        userInfo.setUsedLoginEnum(UsedLoginEnum.MOBILE);
        userInfo.setUserName(registerByMobileRequest.getUserName());
        if(acceptLanguage != null && !"".equals(acceptLanguage)) {
        }
        
        if(userRespond != null) {
        	userInfo.setId(userRespond.getUserId());
            userInfo.setNumericUserId(userRespond.getNumericUserId());
            userInfo.setIsActive(true);
            userInfo.setIsDeleted(false);
        }
        userInfo.setRule(ruleEnum);
        return jwtUtil.generateTokenFromUserInfo(userInfo);
    }

    private AddNewUserRequest mapRegisterByMobileRequestToAddNewUserRequest(RegisterByMobileRequest registerByMobileRequest, RuleEnum rule) {
        AddNewUserRequest addNewUserRequest = new AddNewUserRequest();
        addNewUserRequest.setUserName(registerByMobileRequest.getUserName());
        addNewUserRequest.setBirthDate(registerByMobileRequest.getBirthDate());
        addNewUserRequest.setCountry(registerByMobileRequest.getCountry());
        addNewUserRequest.setProfilePictureUrl(registerByMobileRequest.getProfilePictureUrl());
        addNewUserRequest.setRule(rule.getValue());

        return addNewUserRequest;
    }

	public void updatePassword(String authorization, UpdateLoginByMobilePasswordRequest updateLoginByMobilePasswordRequest) {

		UserInfo userInfo = jwtUtil.getUserInfoFromToken();
		String mobileNumber = userInfo.getMobileNumber();
		log.debug("Changing password for user with mobile number {}", mobileNumber);
		Auth auth = authDao.getAuthDataByMobileNumber(mobileNumber);
		if (auth != null) {
			if (passwordEncoder.matches(updateLoginByMobilePasswordRequest.getCurrentPassword(), auth.getPassword())) {
				String newPassword = updateLoginByMobilePasswordRequest.getNewPassword();
				if (!AuthUtils.isValidPassword(newPassword)) {
					throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "WRONG_NEW_PASSWORD_FORMAT");
				}
				auth.setPassword(passwordEncoder.encode(newPassword));
				authDao.update(auth);
			} else {
				throw new ResponseStatusException(HttpStatus.FORBIDDEN, "WRONG_CURRENT_PASSWORD");
			}

		} else {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "USER_NOT_FOUND");
		}
	}
}
