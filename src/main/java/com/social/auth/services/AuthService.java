package com.social.auth.services;

import com.social.swagger.model.auth.*;
import com.social.swagger.model.auth.*;

import java.time.LocalDate;

import org.springframework.stereotype.Service;

/**
 * @author ayameen
 */
@Service
public interface AuthService {

    /**
     * Delete users info by scheduler-ms, for admin use only
     *
     * @param authorization admin auth token
     * @param deleteAuthByUserIdsRequest request body contains a list of user ids
     * @return DeletePostsByUserIdsRespond, user id with deletion status
     */
    public DeleteAuthByUserIdsRespond deleteAuthByUserIds(String authorization, DeleteAuthByUserIdsRequest deleteAuthByUserIdsRequest);
    
	public void logout(String authorization);

    UserRule getUserRule(String authorization, String userId);

    GetRulesByUserIdsRespond getUsersRules(String authorization, GetRulesByUserIdsRequest getRulesByUserIdsRequest);
    
    UserVerificationStatusRespond verifyBirthday(String authorization, VerifyBirthdayRequest verifyBirthdayRequest);
    
    UserVerificationStatusRespond checkUserVerificationStatus(String deviceId);
    
    GetAllDeviceInfoRespond getBlockedDevices(String authorization);
    
    public void unBlockOrRemoveDevices(String authorization, UnBlockOrRemoveDevicesRequest unBlockDevicesRequest );
    
    public AuthenticateRespond register(RegisterRequest registerRequest, String acceptLanguage);
    
    public AuthenticateRespond login(LoginRequest loginRequest, String acceptLanguage);
    
    public GetUsersCountResponse getNewUsersCount(String authorization, LocalDate fromDate, LocalDate toDate,
			int pageNumber, int pageSize);
}
