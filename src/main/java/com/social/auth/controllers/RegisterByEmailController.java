package com.social.auth.controllers;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.server.ResponseStatusException;

import com.social.auth.consts.AuthConstants;
import com.social.auth.data.mongo.dao.AuthDao;
import com.social.auth.data.mongo.dao.DeviceInfoDao;
import com.social.auth.data.mongo.dao.OtpDao;
import com.social.auth.data.mongo.models.Auth;
import com.social.auth.data.mongo.models.DeviceInfo;
import com.social.auth.data.mongo.models.LoginTypeEnum;
import com.social.auth.data.mongo.models.OtpDTO;
import com.social.auth.gateway.UserApiClient;
import com.social.auth.services.RefreshTokenService;
import com.social.auth.utils.AuthUtils;
import com.social.core.models.RuleEnum;
import com.social.core.models.UsedLoginEnum;
import com.social.core.models.UserInfo;
//import com.social.core.utils.EmailUtil;
import com.social.core.utils.JWTUtil;
import com.social.swagger.called.user.model.AddNewUserRequest;
import com.social.swagger.called.user.model.AddNewUserRespond;
import com.social.swagger.model.auth.AuthenticateRespond;
import com.social.swagger.model.auth.RegisterByEmailRequest;

import lombok.extern.log4j.Log4j2;

@Log4j2
@Controller
public class RegisterByEmailController implements AuthConstants {

//	@Autowired
//	EmailUtil emailUtil;

	JWTUtil jwtUtil;

	private PasswordEncoder passwordEncoder;
	private AuthDao authDao;
	private DeviceInfoDao deviceInfoDao;
	AuthUtils authUtils;
	private UserApiClient userApiClient;
	private final RefreshTokenService refreshTokenService;
	private OtpDao otpDao;

	public RegisterByEmailController(JWTUtil jwtUtil, UserApiClient userApiClient, AuthDao authDao,
			PasswordEncoder passwordEncoder, DeviceInfoDao deviceDao, AuthUtils authUtils,
			RefreshTokenService refreshTokenService, OtpDao otpDao) {
		this.jwtUtil = jwtUtil;
		this.userApiClient = userApiClient;
		this.authDao = authDao;
		this.passwordEncoder = passwordEncoder;
		this.deviceInfoDao = deviceDao;
		this.authUtils = authUtils;
		this.refreshTokenService = refreshTokenService;
		this.otpDao = otpDao;
	}

	 
	@Value("${otp.validate.enabled}")
	private boolean validateOtpEnabled;
	 
	public AuthenticateRespond execute(RegisterByEmailRequest registerByEmailRequest, String acceptLanguage, RuleEnum rule) {
		log.debug("register called withcallUserApiToAddNewUser RegisterByEmailRequest {}", registerByEmailRequest);
        if(validateOtpEnabled) {
            validateOTP(registerByEmailRequest);
        }
        if(!AuthUtils.isValidPassword(registerByEmailRequest.getPassword())){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "WRONG_PASSWORD_FORMAT");
        }
        AuthenticateRespond authenticateRespond = new AuthenticateRespond();
        authenticateRespond.setAccessToken(generateTokenFromUserInfo(registerByEmailRequest,null, acceptLanguage, rule ==null ? RuleEnum.NORMAL: rule));

        AddNewUserRespond addNewUserRespond = callUserApiToAddNewUser(registerByEmailRequest, authenticateRespond, rule ==null ? RuleEnum.NORMAL: rule);

        Auth authData = storeAuthInDB(registerByEmailRequest, addNewUserRespond.getUserId(), rule);

        authenticateRespond.setAccessToken(generateTokenFromUserInfo(registerByEmailRequest,addNewUserRespond, acceptLanguage,authData.getRule()));
        authenticateRespond.setRefreshToken(refreshTokenService.createRefreshToken(authData.getId()).getToken());
        return authenticateRespond;
	}
	
	private void validateOTP(RegisterByEmailRequest registerByEmailRequest) {
        OtpDTO otpData = otpDao.getOtpDataByEmail(registerByEmailRequest.getEmail());
        if(otpData != null && otpData.getOtpNumber().equals(registerByEmailRequest.getOtpCode())){
            if(otpData.getExpiryDate().compareTo(Instant.now()) < 0) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "OTP_EXPIRED");
            }
        }else{
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "WRONG_OTP");
        }
    }
	
	private Auth storeAuthInDB(RegisterByEmailRequest registerByEmailRequest, String userId, RuleEnum rule) {
        Auth auth = new Auth();
        auth.setEmail(registerByEmailRequest.getEmail());
        auth.setUserId(userId);
        auth.setLoginType(LoginTypeEnum.EMAIL);
        auth.setPassword(passwordEncoder.encode(registerByEmailRequest.getPassword()));
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
	
	private AddNewUserRespond callUserApiToAddNewUser(RegisterByEmailRequest registerByEmailRequest,
			AuthenticateRespond authenticateRespond, RuleEnum rule) {
		AddNewUserRequest addNewUserRequest = mapRegisterByEmailRequestToAddNewUserRequest(registerByEmailRequest,
				rule);
		DeviceInfo deviceInfo = null;
		if (Objects.nonNull(registerByEmailRequest.getBirthDate())) {
			addNewUserRequest = authUtils.validateAndUpdateBirthdate(addNewUserRequest, deviceInfo);
		}
		AddNewUserRespond addNewUserRespond = userApiClient.addNewUser("Bearer " + authenticateRespond.getAccessToken(),
				addNewUserRequest);
		if(Objects.nonNull(deviceInfo)) {
			deviceInfo = authUtils.updateDeviceInfo(deviceInfo, addNewUserRespond);
			deviceInfoDao.saveDeviceInfo(deviceInfo);
		}
		return addNewUserRespond;
	}

	private AddNewUserRequest mapRegisterByEmailRequestToAddNewUserRequest(
			RegisterByEmailRequest registerByEmailRequest, RuleEnum rule) {
		AddNewUserRequest addNewUserRequest = new AddNewUserRequest();
		addNewUserRequest.setUserName(registerByEmailRequest.getUserName());
		addNewUserRequest.setBirthDate(registerByEmailRequest.getBirthDate());
		addNewUserRequest.setCountry(registerByEmailRequest.getCountry());
		addNewUserRequest.setProfilePictureUrl(registerByEmailRequest.getProfilePictureUrl());
		addNewUserRequest.setRule(rule.getValue());

		return addNewUserRequest;
	}

	private String generateTokenFromUserInfo(RegisterByEmailRequest registerByEmailRequest,
			AddNewUserRespond userRespond, String acceptLanguage, RuleEnum ruleEnum) {
		UserInfo userInfo;
		userInfo = new UserInfo();

		userInfo.setEmail(registerByEmailRequest.getEmail());
		userInfo.setUsedLoginEnum(UsedLoginEnum.EMAIL);
		userInfo.setUserName(registerByEmailRequest.getUserName());
		
		if(acceptLanguage != null && !"".equals(acceptLanguage)) {
        }
		if (userRespond != null) {
			userInfo.setId(userRespond.getUserId());
			userInfo.setNumericUserId(userRespond.getNumericUserId());
			userInfo.setIsActive(true);
			userInfo.setIsDeleted(false);
		}
		userInfo.setRule(ruleEnum);
		return jwtUtil.generateTokenFromUserInfo(userInfo);
	}

}
