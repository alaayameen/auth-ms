package com.social.auth.controllers;

import com.social.auth.data.mongo.dao.OtpDao;
import com.social.auth.data.mongo.dao.ValidateOtpRepository;
import com.social.auth.utils.AuthUtils;
import com.social.swagger.model.auth.ValidateOTPRequest;
import com.social.swagger.model.auth.ValidateOTPResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;

@Controller
public class ValidateOTPController {

	@Autowired
    AuthUtils authUtils;
	private ValidateOtpRepository validateOtpRepository;
	private OtpDao otpDao;

	public ValidateOTPController(ValidateOtpRepository validateOtpRepository, OtpDao otpDao) {
		this.validateOtpRepository = validateOtpRepository;
		this.otpDao = otpDao;
	}

	public ValidateOTPResponse validateOTP(ValidateOTPRequest validateOPTRequest) {
		return authUtils.validateOTP(validateOPTRequest);
	}
}
