package com.social.auth.controllers;

import com.social.auth.gateway.UserApiClient;
import com.social.auth.services.PasswordService;
import com.social.auth.utils.AuthUtils;
import com.social.swagger.model.auth.ChangePasswordRequest;
import com.social.swagger.model.auth.ResetPasswordRequest;
import com.social.swagger.model.auth.SendForgetPasswordVerificationCodeRequest;
import org.springframework.stereotype.Controller;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Log4j2
@Controller
@AllArgsConstructor
public class PasswordController {

	AuthUtils authUtils;
	UserApiClient userApiClient;
	private PasswordService passwordService;

	public void forgetPassword(SendForgetPasswordVerificationCodeRequest sendForgetPasswordVerificationCodeRequest) {
		log.debug("calling forgetPassword with request {}", sendForgetPasswordVerificationCodeRequest);
		passwordService.forgetPassword(sendForgetPasswordVerificationCodeRequest);
	}

	public void resetPassword(ResetPasswordRequest resetPasswordRequest) {
		log.debug("calling resetPassword with request {}", resetPasswordRequest);
		passwordService.resetPassword(resetPasswordRequest);
	}
	
	public void changePassword(ChangePasswordRequest changePasswordRequest) {
		log.debug("calling ChangePassword with request {}", changePasswordRequest);
		passwordService.changePassword(changePasswordRequest);
	}
}
