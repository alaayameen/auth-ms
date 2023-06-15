package com.social.auth.services.impl;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.Period;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.social.auth.controllers.RegisterByEmailController;
import com.social.auth.controllers.RegisterByMobileController;
import com.social.auth.data.mongo.dao.DeviceInfoDao;
import com.social.auth.data.mongo.dao.OtpRepository;
import com.social.auth.data.mongo.dao.ValidateOtpRepository;
import com.social.auth.gateway.UserApiClient;
import com.social.auth.services.AuthService;
import com.social.auth.services.RefreshTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.social.auth.consts.AuthConstants;
import com.social.auth.controllers.LoginByEmailController;
import com.social.auth.controllers.LoginByMobileController;
import com.social.auth.data.mongo.dao.AuthDao;
import com.social.auth.data.mongo.dao.AuthRepository;
import com.social.auth.data.mongo.dao.DeviceInfoRepository;
import com.social.auth.data.mongo.dao.RefreshTokenRepository;
import com.social.auth.data.mongo.models.Auth;
import com.social.auth.data.mongo.models.DeviceInfo;
import com.social.auth.data.mongo.models.DeviceStatusEnum;
import com.social.auth.utils.AuthUtils;
import com.social.core.models.RuleEnum;
import com.social.core.models.UsedLoginEnum;
import com.social.core.models.UserInfo;
import com.social.core.utils.JWTUtil;
import com.social.swagger.called.user.model.UpdateUserRequest;
import com.social.swagger.called.user.model.UserInfoForAdmin;
import com.social.swagger.model.auth.AuthenticateRespond;
import com.social.swagger.model.auth.DeleteAuthByUserIdsRequest;
import com.social.swagger.model.auth.DeleteAuthByUserIdsRespond;
import com.social.swagger.model.auth.DeleteUsersStatus;
import com.social.swagger.model.auth.DeviceInfoDetails;
import com.social.swagger.model.auth.GetAllDeviceInfoRespond;
import com.social.swagger.model.auth.GetRulesByUserIdsRequest;
import com.social.swagger.model.auth.GetRulesByUserIdsRespond;
import com.social.swagger.model.auth.GetUsersCountResponse;
import com.social.swagger.model.auth.LoginByEmail;
import com.social.swagger.model.auth.LoginByMobile;
import com.social.swagger.model.auth.LoginRequest;
import com.social.swagger.model.auth.RegisterByEmailRequest;
import com.social.swagger.model.auth.RegisterByMobileRequest;
import com.social.swagger.model.auth.RegisterRequest;
import com.social.swagger.model.auth.UnBlockOrRemoveDevicesRequest;
import com.social.swagger.model.auth.UserCountDetails;
import com.social.swagger.model.auth.UserRule;
import com.social.swagger.model.auth.UserVerificationStatusRespond;
import com.social.swagger.model.auth.VerifyBirthdayRequest;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;

/**
 * @author ayameen
 */
@Log4j2
@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService, AuthConstants {

	private JWTUtil jwtUtil;
	AuthUtils authUtil;
	UserApiClient userApiClient;
	AuthRepository authRepository;
	OtpRepository otpRepository;
	private AuthDao authDao;
	private PasswordEncoder passwordEncoder;
	RefreshTokenRepository refreshTokenRepository;
	ValidateOtpRepository validateOtpRepository;
	DeviceInfoDao deviceInfoDao;
	RegisterByMobileController registerByMobileController;
	RegisterByEmailController registerByEmailController;
	LoginByEmailController loginByEmailController;
	LoginByMobileController loginByMobileController;
	private final RefreshTokenService refreshTokenService;
	DeviceInfoRepository deviceInfoRepository;
	
	/**
	 * Delete users info by scheduler-ms, for admin use only
	 *
	 * @param authorization              admin auth token
	 * @param deleteAuthByUserIdsRequest request body contains a list of user ids
	 * @return DeletePostsByUserIdsRespond, user id with deletion status
	 */
	@Override
	public DeleteAuthByUserIdsRespond deleteAuthByUserIds(String authorization,
                                                          DeleteAuthByUserIdsRequest deleteAuthByUserIdsRequest) {
		DeleteAuthByUserIdsRespond deleteAuthByUserIdsRespond = new DeleteAuthByUserIdsRespond();
		deleteAuthByUserIdsRequest.getUsersIds().forEach(userId -> {
			DeleteUsersStatus deleteUsersStatus = new DeleteUsersStatus();
			deleteUsersStatus.setUserId(userId);
			try {
				List<Auth> auths = authRepository.findByUserId(userId);
				List<String> mobileNumbers = auths.stream()
						.filter(auth -> auth.getLoginType().toString().equals("MOBILE")).map(Auth::getMobileNumber)
						.collect(Collectors.toList());
				List<String> authIds = auths.stream().map(Auth::getId).collect(Collectors.toList());
				authRepository.deleteByUserId(userId);
				otpRepository.deleteByMobileNumber(mobileNumbers);
				refreshTokenRepository.deleteByAuthId(authIds);
				validateOtpRepository.deleteByMobileNumber(mobileNumbers);
				deleteUsersStatus.setDeleteStatus(Boolean.TRUE);

			} catch (Exception e) {
				log.error("Failed to delete user: {} auth info", userId);
				deleteUsersStatus.setDeleteStatus(Boolean.FALSE);
			}
			deleteAuthByUserIdsRespond.add(deleteUsersStatus);
		});

		return deleteAuthByUserIdsRespond;
	}

	@Override
	public void logout(String authorization) {
		String userId = jwtUtil.getUserInfoFromToken().getId();
		String adminToken = "Bearer " + jwtUtil.generateTokenForAdminUser();

		log.debug("Logout will update lastActiveDate for user with ID {}!", userId);
		userApiClient.getUserStatusDetailByAdmin(adminToken, userId); //

		// TODO:Add the logout logic in API Gateway
	}

	@Override
	public UserRule getUserRule(String authorization, String userId) {
		Auth rule = authRepository.findRuleByUserId(userId);
		UserRule userRule = new UserRule();
		if (rule != null && rule.getRule() != null) {
			userRule.setRule(rule.getRule().toString());
		}
		return userRule;
	}

	@Override
	public GetRulesByUserIdsRespond getUsersRules(String authorization,
			GetRulesByUserIdsRequest getRulesByUserIdsRequest) {
		GetRulesByUserIdsRespond getRulesByUserIdsRespond = new GetRulesByUserIdsRespond();
		if (getRulesByUserIdsRequest != null) {
			List<Auth> rules = authRepository.findRuleByUserIdIn(getRulesByUserIdsRequest.getUsersIds());
			rules.forEach(item -> {
				UserRule userRule = new UserRule();
				userRule.setRule(item.getRule() != null ? item.getRule().toString() : "");
				userRule.setUserId(item.getUserId());
				getRulesByUserIdsRespond.add(userRule);
			});
		}
		return getRulesByUserIdsRespond;
	}

	@Override
	public UserVerificationStatusRespond verifyBirthday(String authorization,
			VerifyBirthdayRequest verifyBirthdayRequest) {
		log.debug("Verify birthday {}", verifyBirthdayRequest);
		
		String deviceId = null;
		if(deviceId == null) {
				return new UserVerificationStatusRespond()
								.verificationStatus(UserVerificationStatusRespond.VerificationStatusEnum.ACCEPTED);
		}
		
		DeviceInfo deviceInfo = deviceInfoDao.getDeviceInfoByDeviceId(deviceId)
					     .orElse(
					    		 		DeviceInfo.builder()
					    		 		.userIds(new ArrayList<>())
					    		 		.build()
					    		 		);
		
		if (deviceInfo.getDeviceStatus() == DeviceStatusEnum.BLOCKED) {
			return new UserVerificationStatusRespond()
					.verificationStatus(UserVerificationStatusRespond.VerificationStatusEnum.BLOCKED_BY_APP)
					.reason(deviceInfo.getValidation());
		}

		Integer userCurrentAge = Period.between(verifyBirthdayRequest.getBirthday(), LocalDate.now()).getYears();
		Integer storedAge = deviceInfo.getBirthdate() == null ? userCurrentAge:
			Period.between(deviceInfo.getBirthdate(), LocalDate.now()).getYears();
		
		LocalDate actualBirthday = storedAge <  userCurrentAge ? deviceInfo.getBirthdate():
			verifyBirthdayRequest.getBirthday();
		
		String userId = verifyBirthdayRequest.getUserId();
		
		UserVerificationStatusRespond respond = new UserVerificationStatusRespond();
		
		log.debug("Here verifying birthday {} , current {}, stored {} , deviceinfo {} ", verifyBirthdayRequest.getBirthday(), actualBirthday, storedAge, deviceInfo);
		
		//The valid case
		if (userCurrentAge >= AGE_LIMIT && storedAge >= AGE_LIMIT) {
			deviceInfo.setBirthdate(actualBirthday);
			deviceInfo.setDeviceId(deviceId);
			deviceInfo.setDeviceStatus(DeviceStatusEnum.VALID);
			deviceInfo.setValidation(userId != null? VALID_USER: ACCEPTED);
			deviceInfo.setLastTryDate(LocalDateTime.now());
			
			List<String> userIds = deviceInfo.getUserIds();
			if(userIds == null) {
				userIds = new ArrayList<>();
			}
			if(userId != null) {
				userIds.add(userId);
			}
			
			Set<String> userSet = new HashSet<>(userIds);
			deviceInfo.setUserIds(new ArrayList<>(userSet));
						
			deviceInfoDao.saveDeviceInfo(deviceInfo);
			respond.setVerificationStatus(UserVerificationStatusRespond.VerificationStatusEnum.ACCEPTED);
			
		}else {
			deviceInfo.setBirthdate(actualBirthday);
			deviceInfo.setDeviceId(deviceId);
			deviceInfo.setDeviceStatus(DeviceStatusEnum.INVALID);
			deviceInfo.setValidation(UNDERAGE);
			deviceInfo.setLastTryDate(LocalDateTime.now());
			List<String> userIds = deviceInfo.getUserIds();
			if(userIds == null) {
				userIds = new ArrayList<>();
			}
			if(userId != null) {
				userIds.add(userId);
			}
			Set<String> userSet = new HashSet<>(userIds);			
			deviceInfo.setUserIds(new ArrayList<>(userSet));
			
			deviceInfoDao.saveDeviceInfo(deviceInfo);
			respond.setVerificationStatus(UserVerificationStatusRespond.VerificationStatusEnum.REJECTED);
			respond.setReason(UNDERAGE);
		}
		
		
		if (Objects.nonNull(userId) && Objects.nonNull(authorization) 
						&& !verifyBirthdayRequest.isInternal()) {
			
			UpdateUserRequest updateUserRequest = new UpdateUserRequest();
			updateUserRequest.setBirthDate(actualBirthday);

			userApiClient.updateUser(authorization, updateUserRequest);
		}
		
		return respond;
	}

	@Override
	public UserVerificationStatusRespond checkUserVerificationStatus(String deviceId) {
		log.info("checking verify status for device id : {}", deviceId);

		Optional<DeviceInfo> deviceInfoOp = deviceInfoDao.getDeviceInfoByDeviceId(deviceId);
		if (!deviceInfoOp.isPresent()) {
			UserVerificationStatusRespond respond = new UserVerificationStatusRespond();
			respond.setVerificationStatus(UserVerificationStatusRespond.VerificationStatusEnum.USER_NOT_FOUND);

			return respond;
		}

		DeviceInfo deviceInfo = deviceInfoOp.get();
		UserVerificationStatusRespond userVerificationStatusRespond = new UserVerificationStatusRespond();

		if (deviceInfo.getDeviceStatus() == DeviceStatusEnum.VALID) {
			userVerificationStatusRespond.setVerificationStatus(UserVerificationStatusRespond.VerificationStatusEnum.ACCEPTED);
		} else {
			userVerificationStatusRespond.setVerificationStatus(UserVerificationStatusRespond.VerificationStatusEnum.REJECTED);
			userVerificationStatusRespond
					.setReason(String.format("User is rejected due to : %s", deviceInfo.getValidation()));
		}
		return userVerificationStatusRespond;
	}

	@Override
	public GetAllDeviceInfoRespond getBlockedDevices(String authorization) {
		List<DeviceInfo> devicesList =  deviceInfoDao.getDeviceInfoByValidationOrUserStatus(UNDERAGE, DeviceStatusEnum.BLOCKED);
	
		List<DeviceInfoDetails> devicesDetails = new ArrayList<>();
		devicesList.stream().forEach(deviceInfo -> {
			DeviceInfoDetails device = new DeviceInfoDetails().
					birthday(deviceInfo.getBirthdate()).
					deviceId(deviceInfo.getDeviceId()).
					usersIds(deviceInfo.getUserIds()).
					validation(deviceInfo.getValidation());
					
			devicesDetails.add(device);
		});
		return new GetAllDeviceInfoRespond().data(devicesDetails);
	}

	@Override
	public void unBlockOrRemoveDevices(String authorization, UnBlockOrRemoveDevicesRequest unBlockDevicesRequest) {
		log.debug("Call unBlockDevices to unblock or remove list of user devices");
		if (unBlockDevicesRequest.isIsRemoveDevices()) {
			unBlockDevicesRequest.getDevicesIds().forEach(deviceId -> deviceInfoDao.deleteByDeviceId(deviceId));
		} else {
		  deviceInfoDao.UnblockDevices(unBlockDevicesRequest.getDevicesIds());
		}
	}
	
	

	@Override
	public AuthenticateRespond register(RegisterRequest registerRequest, String acceptLanguage) {
		String mobileOrEmail = registerRequest.getMobileOrEmail();
		if (Pattern.compile(EMAIL_VALIDATION).matcher(mobileOrEmail).matches()) {
			RegisterByEmailRequest  registerByEmailRequest = new RegisterByEmailRequest();
			registerByEmailRequest.setBirthDate(registerRequest.getBirthDate());
			registerByEmailRequest.setCountry(registerRequest.getCountry());
			registerByEmailRequest.setEmail(mobileOrEmail);
			registerByEmailRequest.setPassword(registerRequest.getPassword());
			registerByEmailRequest.setProfilePictureUrl(registerRequest.getProfilePictureUrl());
			registerByEmailRequest.setUserName(registerRequest.getUserName());
			registerByEmailRequest.setOtpCode(registerRequest.getOtpCode());
			
			return registerByEmailController.execute(registerByEmailRequest, acceptLanguage, null);
		
		} else if (Pattern.compile(MOBILE_VALIDATION).matcher(mobileOrEmail).matches()) {
			
			RegisterByMobileRequest registerByMobileRequest = new RegisterByMobileRequest();
			registerByMobileRequest.setBirthDate(registerRequest.getBirthDate());
			registerByMobileRequest.setCountry(registerRequest.getCountry());
			registerByMobileRequest.setMobileNumber(registerRequest.getMobileOrEmail());
			registerByMobileRequest.setPassword(registerRequest.getPassword());
			registerByMobileRequest.setProfilePictureUrl(registerRequest.getProfilePictureUrl());
			registerByMobileRequest.setUserName(registerRequest.getUserName());
			registerByMobileRequest.setOtpCode(registerRequest.getOtpCode());
			
			return registerByMobileController.execute(registerByMobileRequest, acceptLanguage, null);
		} 
		
		log.error("Registration failed due to not valid email or mobile : {}", mobileOrEmail);
		throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "NOT_VALID_REGISTRATION_DETAILS");
		
	}

	@Override
	public AuthenticateRespond login(LoginRequest loginRequest, String acceptLanguage) {
		String loginValue = loginRequest.getLoginValue();
		
		if (Pattern.compile(EMAIL_VALIDATION).matcher(loginValue).matches()) {
			LoginByEmail loginByEmail = new LoginByEmail();
			loginByEmail.setEmail(loginRequest.getLoginValue());
			loginByEmail.setPassword(loginRequest.getPassword());
			loginByEmail.setRestoreAccount(loginRequest.isRestoreAccount());
			return loginByEmailController.loginByEmail(loginByEmail, acceptLanguage);
		} else if (Pattern.compile(MOBILE_VALIDATION).matcher(loginValue).matches()) {
			LoginByMobile loginByMobile = new LoginByMobile();
			loginByMobile.setMobileNumber(loginValue);
			loginByMobile.setPassword(loginRequest.getPassword());
			loginByMobile.setRestoreAccount(loginRequest.isRestoreAccount());
			return loginByMobileController.loginByMobile(loginByMobile, acceptLanguage);
		}
		
		String adminToken = "Bearer " + jwtUtil.generateTokenForAdminUser();
		UserInfoForAdmin userInfoForAdmin = userApiClient.getUserDetailByUsername(adminToken, loginValue);
		if(Objects.nonNull(userInfoForAdmin) && Objects.nonNull(userInfoForAdmin.getUserId())) {
			return loginByUsername(loginValue, loginRequest, userInfoForAdmin, acceptLanguage);
		} else {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND,"USER_NOT_FOUND");
		}
		
	}
	
	
	public AuthenticateRespond loginByUsername(String username, LoginRequest loginRequest, UserInfoForAdmin userInfoForAdmin, String acceptLanguage){
        log.debug("loginByUsername called with loginByUsername {}", username);
        
        Auth authData = authDao.getByUserId(userInfoForAdmin.getUserId());
        log.debug("loginByMobile authData {}", authData);
        if(authData != null) {
            if (passwordEncoder.matches(loginRequest.getPassword(), authData.getPassword())) {
            	String adminToken = "Bearer " + jwtUtil.generateTokenForAdminUser();
                log.debug("loginByUsername  {}", userInfoForAdmin);
                
                if (userInfoForAdmin != null) {
                    if (Boolean.TRUE.equals(userInfoForAdmin.isIsDeleted())) {
                        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "DELETED_USER");
                    }

                    if (Boolean.FALSE.equals(userInfoForAdmin.isActive())) {
                        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "USER_IS_DEACTIVATED");
                    }

                    if (Boolean.TRUE.equals(userInfoForAdmin.isMarkedForDelete())) {
                        if (Boolean.TRUE.equals(loginRequest.isRestoreAccount())) {
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

                AuthenticateRespond authenticateRespond = new AuthenticateRespond();
                authenticateRespond.setAccessToken(generateTokenFromUserInfo(userInfoForAdmin, authData, acceptLanguage, RuleEnum.NORMAL));
                authenticateRespond.setRefreshToken(refreshTokenService.createRefreshToken(authData.getId()).getToken());
                
                log.debug("loginByUsername token are generated {}", authenticateRespond);
                return authenticateRespond;
            } else {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "WRONG_EMAIL_PASSWORD");
            }
        }
        throw new ResponseStatusException(HttpStatus.NOT_FOUND,"USER_NOT_FOUND");
    }
	
	 private String generateTokenFromUserInfo( UserInfoForAdmin userInfoForAdmin, Auth authData, String acceptLanguage, RuleEnum ruleEnum) {
	        UserInfo userInfo;

	        userInfo = new UserInfo();
	        userInfo.setId(userInfoForAdmin.getUserId());
	        
	        if(Objects.nonNull(authData.getMobileNumber())) {
	        	userInfo.setMobileNumber(authData.getMobileNumber());
	        	userInfo.setUsedLoginEnum(UsedLoginEnum.MOBILE);
	        } else if (Objects.nonNull(authData.getEmail())) {
	        	userInfo.setEmail(authData.getEmail());
	        	userInfo.setUsedLoginEnum(UsedLoginEnum.EMAIL);
	        } else {
	        	throw new ResponseStatusException(HttpStatus.FORBIDDEN, "GENERATE_TOKEN_FAILED");
	        }
	        
	        //userInfo.setUsedLoginEnum(authData.getLoginType());
	        if (userInfoForAdmin != null) {
	            userInfo.setIsActive(userInfoForAdmin.isActive());
	            userInfo.setIsDeleted(userInfoForAdmin.isIsDeleted());
	            userInfo.setUserName(userInfoForAdmin.getUserName());
	            userInfo.setNumericUserId(userInfoForAdmin.getNumericUserId());
	        }

	        if(acceptLanguage != null && !"".equals(acceptLanguage)) {
	        }
	        userInfo.setRule(ruleEnum);

	        jwtUtil.generateTokenFromUserInfo(userInfo);
	        return jwtUtil.generateTokenFromUserInfo(userInfo);
	    }
	
	 public GetUsersCountResponse getNewUsersCount(String authorization, LocalDate fromDate, LocalDate toDate,
				int pageNumber, int pageSize) {
		 List<UserCountDetails> newUsersList = new ArrayList<>();

			long totalNumberOfDays = authUtil.getNumberOfDaysBetweenDates(fromDate, toDate);

			boolean isPageNumberExisting = (pageNumber - 1) * pageSize <= totalNumberOfDays;
			boolean isLastPage = authUtil.isLastPage(pageNumber, pageSize, totalNumberOfDays);

			LocalDate startDateForPaging = fromDate.plusDays((pageNumber - 1) * pageSize);
			LocalDate endDateForPaging = !isLastPage ? startDateForPaging.plusDays(pageSize - 1) : toDate;

			log.debug("startDateForPaging is: " + startDateForPaging);
			log.debug("endDateForPaging is: " + endDateForPaging);

			if (isPageNumberExisting) {
				newUsersList = deviceInfoDao.getNewUsersCount(authorization, startDateForPaging,
						endDateForPaging.plusDays(1), (pageNumber - 1) * pageSize, pageSize);
				// Filling non-existing dates in DB with '0' value for count
				if (newUsersList.size() < pageSize) {
					authUtil.appendingZeroCountForNonExistingDateRecords(startDateForPaging, endDateForPaging,
							newUsersList);
				}
			}
			log.debug("newUsersList size is: " + newUsersList.size());
			for (UserCountDetails newUserDetails : newUsersList) {
				log.debug("newUserDetails date is: {}, and it has number of new users equals to {}.",
						newUserDetails.getDate(), newUserDetails.getCount());

			}

			GetUsersCountResponse getnewUsersCountResponse = new GetUsersCountResponse();
			getnewUsersCountResponse.setUsersCountList(newUsersList);
			return getnewUsersCountResponse;	 
		 
	 }
}
