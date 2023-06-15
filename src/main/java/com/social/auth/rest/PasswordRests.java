package com.social.auth.rest;

import com.social.auth.controllers.PasswordController;
import com.social.swagger.model.auth.ResetPasswordRequest;
import com.social.swagger.model.auth.SendForgetPasswordVerificationCodeRequest;
import com.social.auth.controllers.*;
import com.social.swagger.api.auth.PasswordApi;
import com.social.swagger.model.auth.*;
import io.swagger.annotations.ApiParam;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@AllArgsConstructor
public class PasswordRests implements PasswordApi {

	private PasswordController passwordController;

	@Override
	public ResponseEntity<Void> forgetPassword(
			@ApiParam(value = "") @Valid @RequestBody SendForgetPasswordVerificationCodeRequest sendForgetPasswordVerificationCodeRequest,
			@ApiParam(value = "List of acceptable human languages for response") @RequestHeader(value = "Accept-Language", required = false) String acceptLanguage) {
		passwordController.forgetPassword(sendForgetPasswordVerificationCodeRequest);
		return ResponseEntity.noContent().build();
	}

	@Override
	public ResponseEntity<Void> resetPassword(
			@ApiParam(value = "") @Valid @RequestBody ResetPasswordRequest resetPasswordRequest,
			@ApiParam(value = "List of acceptable human languages for response") @RequestHeader(value = "Accept-Language", required = false) String acceptLanguage) {
		passwordController.resetPassword(resetPasswordRequest);
		return ResponseEntity.noContent().build();
	}

	@Override
	public ResponseEntity<Void> changePassword(
			@ApiParam(value = "") @Valid @RequestBody ChangePasswordRequest changePasswordRequest,
			@ApiParam(value = "List of acceptable human languages for response") @RequestHeader(value = "Accept-Language", required = false) String acceptLanguage) {
		passwordController.changePassword(changePasswordRequest);
		return ResponseEntity.noContent().build();
	}
}
