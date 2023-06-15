package com.social.auth.services.impl;

import java.time.LocalDate;

import com.social.auth.services.PasswordService;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.social.auth.data.mongo.dao.AuthDao;
import com.social.auth.data.mongo.dao.AuthRepository;
import com.social.auth.data.mongo.dao.OtpRepository;
import com.social.auth.data.mongo.dao.RefreshTokenRepository;
import com.social.auth.data.mongo.dao.ValidateOtpRepository;
import com.social.auth.data.mongo.models.Auth;
import com.social.auth.gateway.UserApiClient;
import com.social.auth.utils.AuthUtils;
import com.social.core.utils.JWTUtil;
import com.social.swagger.called.user.model.UserInfoForAdmin;
import com.social.swagger.model.auth.ChangePasswordRequest;
import com.social.swagger.model.auth.ResetPasswordRequest;
import com.social.swagger.model.auth.SendForgetPasswordVerificationCodeRequest;
import com.social.swagger.model.auth.SendVerificationCodeRequest;
import com.social.swagger.model.auth.ValidateOTPRequest;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;

/**
 * @author ideek
 */
@Log4j2
@Service
@AllArgsConstructor
public class PasswordServiceImpl implements PasswordService {

	AuthRepository authRepository;
	OtpRepository otpRepository;
	RefreshTokenRepository refreshTokenRepository;
	ValidateOtpRepository validateOtpRepository;
	private AuthDao authDao;
	private JWTUtil jwtUtil;
	UserApiClient userApiClient;
	AuthUtils authUtils;
	private PasswordEncoder passwordEncoder;

	@Override
	public void forgetPassword(SendForgetPasswordVerificationCodeRequest sendForgetPasswordVerificationCodeRequest) {
		String mobileNumber = sendForgetPasswordVerificationCodeRequest.getMobileNumber().replace("+", "");

		log.debug("Checking whether user with mobile number {} exists in Auth or not!", mobileNumber);
		Auth authData = authDao.getAuthDataByMobileNumber(mobileNumber);
		if (authData != null) {
			String adminToken = "Bearer " + jwtUtil.generateTokenForAdminUser();
			UserInfoForAdmin userInfoForAdmin = userApiClient.getUserStatusDetailByAdmin(adminToken,
					authData.getUserId());
			if (userInfoForAdmin != null) {
				if (Boolean.TRUE.equals(userInfoForAdmin.isIsDeleted())) {
					throw new ResponseStatusException(HttpStatus.FORBIDDEN, "DELETED_USER");
				}
				if (Boolean.TRUE.equals(userInfoForAdmin.isMarkedForDelete())) {
					if (Boolean.TRUE.equals(sendForgetPasswordVerificationCodeRequest.isRestoreAccount())) {
						if (userInfoForAdmin.getCanRollbackDeleteDate() != null
								&& LocalDate.now().isBefore(userInfoForAdmin.getCanRollbackDeleteDate())) {
							userInfoForAdmin.setMarkedForDelete(false);
							userApiClient.rollbackUserDeleteStatus(adminToken, authData.getUserId());
						} else {
							throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ACCOUNT_MARKED_FOR_DELETE");
						}
					} else {
						throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ACCOUNT_MARKED_FOR_DELETE");
					}
				}
			}
			log.debug("Sending OTP code to mobile number {}", mobileNumber);
			generateAndSend(mobileNumber);

		} else {
			log.debug("User with mobile number {}, is not found in Auth.", mobileNumber);
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "USER_NOT_FOUND");
		}

	}

	/**
	 * This method takes mobileNumber as String and map it to
	 * SendVerificationCodeRequest before calling main 'generateAndSend' method
	 * 
	 * @param mobileNumber
	 */
	public void generateAndSend(String mobileNumber) {
		SendVerificationCodeRequest sendVerificationCodeReques = new SendVerificationCodeRequest();
		sendVerificationCodeReques.setMobileNumber(mobileNumber);
		authUtils.generateAndSend(sendVerificationCodeReques);
	}

	@Override
	public void resetPassword(ResetPasswordRequest resetPasswordRequest) {

		String mobileNumber = resetPasswordRequest.getMobileNumber().replace("+", "");
		String otpCode = resetPasswordRequest.getOtpCode();

		ValidateOTPRequest validateOTPRequest = new ValidateOTPRequest();
		validateOTPRequest.setMobileNumber(mobileNumber);
		validateOTPRequest.setOtpCode(otpCode);

		log.debug("Validating OTP code {} for mobile number {} exists in OTP.", otpCode, mobileNumber);

		if (authUtils.validateOTP(validateOTPRequest).isValid()) {
			String newPassword = resetPasswordRequest.getPassword();
			if (!AuthUtils.isValidPassword(newPassword)) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "WRONG_PASSWORD_FORMAT");
			}
			Auth auth = authDao.getAuthDataByMobileNumber(mobileNumber);
			if (auth != null) {
				auth.setPassword(passwordEncoder.encode(newPassword));
				authDao.update(auth);
			} else {
				log.debug("User with mobile number {}, is not found in Auth.", mobileNumber);
				throw new ResponseStatusException(HttpStatus.NOT_FOUND, "USER_NOT_FOUND");
			}
		} else {
			log.debug("{} OTP Code is not valid!", resetPasswordRequest.getOtpCode());
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "OTP_CODE_NOT_FOUND");
		}
	}

	@Override
	public void changePassword(ChangePasswordRequest changePasswordRequest) {

		String mobileNumber = changePasswordRequest.getMobileNumber().replace("+", "");
		log.debug("Changing password for user with mobile number {}", mobileNumber);

		Auth authData = authDao.getAuthDataByMobileNumber(mobileNumber);
		log.debug("changePassword authData {}", authData);

		if (authData != null) {
			if (passwordEncoder.matches(changePasswordRequest.getCurrentPassword(), authData.getPassword())) {
				String newPassword = changePasswordRequest.getNewPassword();
				if (!AuthUtils.isValidPassword(newPassword)) {
					throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "WRONG_NEW_PASSWORD_FORMAT");
				}
				authData.setPassword(passwordEncoder.encode(newPassword));
				authDao.update(authData);

			} else {
				throw new ResponseStatusException(HttpStatus.FORBIDDEN, "WRONG_CURRENT_PASSWORD");
			}
		} else {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "USER_NOT_FOUND");
		}
	}

}
