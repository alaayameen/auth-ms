package com.social.auth.rest;

import com.social.swagger.model.auth.ValidateOTPRequest;
import com.social.auth.controllers.GenerateOtpController;
import com.social.auth.controllers.ValidateOTPController;
import com.social.swagger.api.auth.OtpApi;
import com.social.swagger.model.auth.SendVerificationCodeRequest;
import com.social.swagger.model.auth.ValidateOTPResponse;
import io.swagger.annotations.ApiParam;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@AllArgsConstructor
public class OtpRests implements OtpApi {

    private GenerateOtpController generateAndSend;
    private ValidateOTPController validateOTPController;

    @Override
    public ResponseEntity<Void> generateAndSend(@ApiParam(value = ""  )  @Valid @RequestBody SendVerificationCodeRequest sendVerificationCode,@ApiParam(value = "List of acceptable human languages for response" ) @RequestHeader(value="Accept-Language", required=false) String acceptLanguage){
        generateAndSend.generateAndSend(sendVerificationCode);
        return ResponseEntity.ok().build();
    }
   
    @Override
    public ResponseEntity<ValidateOTPResponse> validateOTP(@ApiParam(value = ""  )  @Valid @RequestBody ValidateOTPRequest validateOPTRequest, @ApiParam(value = "List of acceptable human languages for response" ) @RequestHeader(value="Accept-Language", required=false) String acceptLanguage) {
        return ResponseEntity.ok(validateOTPController.validateOTP(validateOPTRequest));
    }
}
