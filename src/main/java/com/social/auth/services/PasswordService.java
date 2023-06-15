package com.social.auth.services;

import org.springframework.stereotype.Service;

import com.social.swagger.model.auth.ChangePasswordRequest;
import com.social.swagger.model.auth.ResetPasswordRequest;
import com.social.swagger.model.auth.SendForgetPasswordVerificationCodeRequest;

/**
 * @author ideek
 */
@Service
public interface PasswordService {

	void forgetPassword(SendForgetPasswordVerificationCodeRequest sendForgetPasswordVerificationCodeRequest);

	void resetPassword(ResetPasswordRequest resetPasswordRequest);
	
	void changePassword(ChangePasswordRequest changePasswordRequest);
}
