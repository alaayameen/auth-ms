package com.social.auth.rest;
import com.social.auth.controllers.*;
import com.social.swagger.model.auth.*;
import com.social.auth.controllers.*;
import com.social.swagger.api.auth.AuthApi;
import com.social.swagger.model.auth.*;
import io.swagger.annotations.ApiParam;
import lombok.AllArgsConstructor;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

import javax.validation.Valid;


@RestController
@AllArgsConstructor
    public class AuthenticationRests implements AuthApi {

    private final RegisterByMobileController registerByMobileController;
    private final LoginByMobileController loginByMobileController;
    private final LoginByFacebookController loginByFacebookController;
    private final RefreshTokenController refreshTokenController;
    private final LoginByGoogleController loginByGoogleController;
    private final LoginByAppleController loginByAppleController;
    private final AuthController authController;

    @Override
    public ResponseEntity<DeleteAuthByUserIdsRespond> deleteAuthByUserIds(@ApiParam(value = "" ,required=true) @RequestHeader(value="Authorization", required=true) String authorization,
                                                                          @ApiParam(value = ""  )  @Valid @RequestBody DeleteAuthByUserIdsRequest deleteAuthByUserIdsRequest) {
        return ResponseEntity.ok(authController.deleteAuthByUserIds(authorization, deleteAuthByUserIdsRequest));

    }

    @Override
    public ResponseEntity<UserRule> getUserRule(String authorization, String userId) {
        return ResponseEntity.ok(authController.getUserRule(authorization, userId));
    }

    @Override
    public ResponseEntity<GetRulesByUserIdsRespond> getUsersRules(String authorization, @Valid GetRulesByUserIdsRequest getRulesByUserIdsRequest) {
        return ResponseEntity.ok(authController.getUsersRules(authorization, getRulesByUserIdsRequest));
    }

    @Override
    public ResponseEntity<AuthenticateRespond> loginByApple(@ApiParam(value = ""  )  @Valid @RequestBody LoginByAppleRequest loginByAppleRequest, @ApiParam(value = "List of acceptable human languages for response" ) @RequestHeader(value="Accept-Language", required=false) String acceptLanguage) {
        return ResponseEntity.ok(loginByAppleController.loginByApple(loginByAppleRequest, acceptLanguage));
    }

    @Override
    public ResponseEntity<AuthenticateRespond> loginByFacebook(@ApiParam(value = ""  )  @Valid @RequestBody LoginByFacebookRequest loginByFacebookRequest, @ApiParam(value = "List of acceptable human languages for response" ) @RequestHeader(value="Accept-Language", required=false) String acceptLanguage) {
        return ResponseEntity.ok(loginByFacebookController.loginByFacebook(loginByFacebookRequest, acceptLanguage));
    }

    @Override
    public ResponseEntity<AuthenticateRespond> loginByGoogle(@ApiParam(value = ""  )  @Valid @RequestBody LoginByGoogleRequest loginByGoogleRequest,@ApiParam(value = "List of acceptable human languages for response" ) @RequestHeader(value="Accept-Language", required=false) String acceptLanguage) {
        return ResponseEntity.ok(loginByGoogleController.loginByGoogle(loginByGoogleRequest, acceptLanguage));
    }

    @Override
    public ResponseEntity<AuthenticateRespond> loginByMobile(@ApiParam(value = ""  )  @Valid @RequestBody LoginByMobile loginByMobileRequest,@ApiParam(value = "List of acceptable human languages for response" ) @RequestHeader(value="Accept-Language", required=false) String acceptLanguage) {
        return ResponseEntity.ok(loginByMobileController.loginByMobile(loginByMobileRequest, acceptLanguage));
    }

    @Override
    public ResponseEntity<RefreshTokenRespond> refreshToken(@ApiParam(value = ""  )  @Valid @RequestBody RefreshTokenRequest refreshTokenRequest,@ApiParam(value = "List of acceptable human languages for response" ) @RequestHeader(value="Accept-Language", required=false) String acceptLanguage) {
        return ResponseEntity.ok(refreshTokenController.refreshToken(refreshTokenRequest, acceptLanguage));
    }

    @Override
    public ResponseEntity<AuthenticateRespond> registerByMobile(@ApiParam(value = ""  )  @Valid @RequestBody RegisterByMobileRequest registerByMobileRequest,@ApiParam(value = "List of acceptable human languages for response" ) @RequestHeader(value="Accept-Language", required=false) String acceptLanguage){
        return ResponseEntity.ok(registerByMobileController.execute(registerByMobileRequest, acceptLanguage, null));
    }

    @Override
    public ResponseEntity<Void> updatePasswordForLoginByMobile(@ApiParam(value = "" ,required=true) @RequestHeader(value="Authorization", required=true) String authorization,@ApiParam(value = ""  )  @Valid @RequestBody UpdateLoginByMobilePasswordRequest updateLoginByMobilePasswordRequest) {
         registerByMobileController.updatePassword(authorization,updateLoginByMobilePasswordRequest);
        return ResponseEntity.noContent().build();
    }

	@Override
	public ResponseEntity<Void> logout(
			@ApiParam(value = "", required = true) @RequestHeader(value = "Authorization", required = true) String authorization) {
		authController.logout(authorization);
		return ResponseEntity.noContent().build();
	}

	@Override
	public ResponseEntity<Void> registerByAdmin(
			@ApiParam(value = "" ,required=true) @RequestHeader(value="Authorization", required=true) String authorization,
			@ApiParam(value = "by default it will be SYTEM_CONTENT", allowableValues = "ADMIN, SYSTEM_CONTENT, TESTING", defaultValue = "SYSTEM_CONTENT") @Valid @RequestParam(value = "userRule", required = false, defaultValue="SYSTEM_CONTENT") String userRule,@ApiParam(value = ""  )  @Valid @RequestBody List<RegisterByMobileRequest> registerByAdminRequest,
			@ApiParam(value = "List of acceptable human languages for response" ) @RequestHeader(value="Accept-Language", required=false) String acceptLanguage){
		registerByMobileController.regesterByAdmin(registerByAdminRequest, userRule, acceptLanguage);
		return ResponseEntity.noContent().build();
	}

	@Override
	public ResponseEntity<UserVerificationStatusRespond> verifyBirthday(
			@ApiParam(value = "" ,required=false) @RequestHeader(value="Authorization", required=false) String authorization,
			@ApiParam(value = ""  )  @Valid @RequestBody VerifyBirthdayRequest verifyBirthdayRequest){
		return ResponseEntity.ok(authController.verifyBirthday(authorization, verifyBirthdayRequest));
	}

	@Override
	public ResponseEntity<UserVerificationStatusRespond> checkUserVerificationStatus(
			@ApiParam(value = "" ,required=true) @RequestHeader(value="deviceid", required=true) String deviceId) {
		return ResponseEntity.ok(authController.checkUserVerificationStatus(deviceId));
	}

	@Override
	public ResponseEntity<GetAllDeviceInfoRespond> getBlockedDevices(
			@ApiParam(value = "" ,required=true) @RequestHeader(value="Authorization", required=true) String authorization) {
		return ResponseEntity.ok(authController.getBlockedDevices(authorization));
	}

	@Override
	public ResponseEntity<Void> unBlockOrRemoveDevices (
			@ApiParam(value = "" ,required=true) @RequestHeader(value="Authorization", required=true) String authorization,
			@ApiParam(value = "" ,required=true) @RequestHeader(value="unBlockDevicesRequest", required=true) UnBlockOrRemoveDevicesRequest unBlockOrRemoveDevicesRequest) {
		authController.unBlockOrRemoveDevices(authorization, unBlockOrRemoveDevicesRequest);
		return ResponseEntity.noContent().build();
	}

	@Override
	public ResponseEntity<AuthenticateRespond> register(@Valid RegisterRequest registerRequest, String acceptLanguage) {
		return ResponseEntity.ok(authController.register(registerRequest, acceptLanguage));
	}

	@Override
	public ResponseEntity<AuthenticateRespond> login(@Valid LoginRequest loginRequest, String acceptLanguage) {
		return ResponseEntity.ok(authController.login(loginRequest, acceptLanguage)); 
	}

	@Override
	public ResponseEntity<GetUsersCountResponse> getNewUsersCount(@ApiParam(value = "", required = true) @RequestHeader(value = "Authorization", required = true) String authorization,
			@ApiParam(value = "fromDate: the start date to get info about number of new users", required = true) @PathVariable("fromDate") @DateTimeFormat(pattern = "yyyy-MM-dd") LocalDate fromDate,
			@ApiParam(value = "fromDate: the start date to get info about number of new users", required = true) @PathVariable("toDate") @DateTimeFormat(pattern = "yyyy-MM-dd") LocalDate toDate,
			@ApiParam(value = "Page Number to get.", defaultValue = "1") @Valid @RequestParam(value = "page", required = false, defaultValue = "1") BigDecimal page,
			@ApiParam(value = "page size of items to return.", defaultValue = "10") @Valid @RequestParam(value = "size", required = false, defaultValue = "10") BigDecimal size) {
		return ResponseEntity.ok(authController.getNewUsersCount(authorization, fromDate, toDate, page, size));
	}

	
}
