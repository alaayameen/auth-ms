package com.social.auth.controllers;

import com.social.auth.utils.AuthUtils;
import com.social.swagger.model.auth.SendVerificationCodeRequest;
import org.springframework.stereotype.Controller;

import lombok.AllArgsConstructor;

@Controller
@AllArgsConstructor
public class GenerateOtpController {

	AuthUtils authUtils;

	public void generateAndSend(SendVerificationCodeRequest sendVerificationCode) {
		authUtils.generateAndSend(sendVerificationCode);
	}
}
