package com.social.auth.controllers;

import com.social.swagger.model.auth.*;
import com.social.core.models.UserInfo;
import com.social.core.utils.JWTUtil;
import com.social.auth.services.AuthService;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Controller;

import javax.validation.Valid;
import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * @author ayameen
 */
@Log4j2
@Controller
@AllArgsConstructor
public class AuthController {

    AuthService authService;
    private JWTUtil jwtUtil;
    /**
     * Delete users info by scheduler-ms, for admin use only
     *
     * @param authorization admin auth token
     * @param deleteAuthByUserIdsRequest request body contains a list of user ids
     * @return DeletePostsByUserIdsRespond, user id with deletion status
     */
    public DeleteAuthByUserIdsRespond deleteAuthByUserIds(String authorization, DeleteAuthByUserIdsRequest deleteAuthByUserIdsRequest) {
        log.debug("A request to delete auth info for user ids {}", deleteAuthByUserIdsRequest.getUsersIds());
        DeleteAuthByUserIdsRespond retrieveFollowingsStoriesRespond = authService.deleteAuthByUserIds(authorization, deleteAuthByUserIdsRequest);
        log.debug("Users auth info is successfully deleted for user ids {}", deleteAuthByUserIdsRequest.getUsersIds());
        return retrieveFollowingsStoriesRespond;
    }
    
	public void logout(String authorization) {
		UserInfo userInfo = jwtUtil.getUserInfoFromToken();
		log.debug("logout for userInfo {}", userInfo);
		authService.logout(authorization);
	}

    public UserRule getUserRule(String authorization, String userId) {
        log.debug("get userRule, userId: {}", userId);
        UserRule rule = authService.getUserRule(authorization, userId);
        log.debug("userRule called successfully, userId: {}", userId);
        return rule;
    }

    public GetRulesByUserIdsRespond getUsersRules(String authorization, GetRulesByUserIdsRequest getRulesByUserIdsRequest) {
        log.debug("get getUsersRules, userId: {}", getRulesByUserIdsRequest);
        GetRulesByUserIdsRespond rule = authService.getUsersRules(authorization, getRulesByUserIdsRequest);
        log.debug("getUsersRules called successfully, userIds: {}", getRulesByUserIdsRequest.getUsersIds());
        return rule;
    }
    
    public UserVerificationStatusRespond verifyBirthday(String authorization, @Valid VerifyBirthdayRequest verifyBirthdayRequest) {
    	log.debug("verifing birthdate {}", verifyBirthdayRequest.getBirthday());
    	return authService.verifyBirthday(authorization, verifyBirthdayRequest);
    	
    }
    
    public UserVerificationStatusRespond checkUserVerificationStatus(String deviceId) {
    	log.debug("get verification status for device Id {}", deviceId);
    	return authService.checkUserVerificationStatus(deviceId);
    }
    
    public GetAllDeviceInfoRespond getBlockedDevices(String authorization) {
    	return authService.getBlockedDevices(authorization);
    }
    
    public void unBlockOrRemoveDevices(String authorization, UnBlockOrRemoveDevicesRequest unBlockDevicesRequest ) {
    	authService.unBlockOrRemoveDevices(authorization, unBlockDevicesRequest);
    }
    
    public AuthenticateRespond register(RegisterRequest registerRequest, String acceptLanguage) {
    	return authService.register(registerRequest, acceptLanguage);
    }
    
    public AuthenticateRespond login(LoginRequest loginRequest, String acceptLanguage) {
    	return authService.login(loginRequest, acceptLanguage);
    }
    
    public GetUsersCountResponse getNewUsersCount(String authorization, LocalDate fromDate, LocalDate toDate,
			BigDecimal page, BigDecimal size) {
		return authService.getNewUsersCount(authorization, fromDate, toDate, page.intValue(), size.intValue());
	}
}
