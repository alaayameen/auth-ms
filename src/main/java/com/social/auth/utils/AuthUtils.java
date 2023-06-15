package com.social.auth.utils;

import com.social.auth.consts.AuthConstants;
import com.social.auth.data.mongo.dao.OtpDao;
import com.social.auth.data.mongo.dao.ValidateOtpRepository;
import com.social.auth.data.mongo.models.DeviceInfo;
import com.social.auth.data.mongo.models.DeviceStatusEnum;
import com.social.auth.data.mongo.models.OtpDTO;
import com.social.auth.data.mongo.models.ValidateOtpDTO;
import com.social.core.utils.JWTUtil;
import com.social.swagger.called.user.model.AddNewUserRequest;
import com.social.swagger.called.user.model.AddNewUserRespond;
import com.social.swagger.model.auth.SendVerificationCodeRequest;
import com.social.swagger.model.auth.UserCountDetails;
import com.social.swagger.model.auth.ValidateOTPRequest;
import com.social.swagger.model.auth.ValidateOTPResponse;
import com.vonage.client.VonageClient;
import com.vonage.client.sms.MessageStatus;
import com.vonage.client.sms.SmsSubmissionResponse;
import com.vonage.client.sms.messages.TextMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.server.ResponseStatusException;

import javax.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.*;
import java.util.stream.Collectors;

@Component
@Log4j2
@RequiredArgsConstructor
public class AuthUtils implements AuthConstants {
	
	private JWTUtil jwtUtil;
	
//	@Autowired
//    EmailUtil emailUtil;
	
	@Value("${spring.mail.noreply}")			
	private String noReplyEmail;			
	        			
    @Value("${spring.mail.filePath}")			
	private String verificationFilePath;
	
	@Value("${otp.validate.maxNumberOfAttempts}")
	private int maxNumberOfAttempts;

	@Value("${otp.validate.restMaxNumberOfAttemptsDurationMs}")
	private Long restMaxNumberOfAttemptsDurationMs;

	@Value("${otp.generate.sms.brandName}")
	private String VONAGE_BRAND_NAME;

	@Value("${otp.generate.durationMs}")
	private Long otpDTODurationMs;

	@Value("${otp.generate.sms.apiKey}")
	private String VONAGE_API_KEY;

	@Value("${otp.generate.sms.apiSecret}")
	private String VONAGE_API_SECRET;

	private final ValidateOtpRepository validateOtpRepository;
	private final OtpDao otpDao;
	private VonageClient client;
	private Random rnd = new Random();

	/*
	 * Will use simple Regex for development purpose. And will back to following
	 * Regex later on. 
	 * private final static String PASS_REGEX = "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%!&*]).{8,20}$";
	 */
	private final static String PASS_REGEX = "^(?=.*[\\da-zA-Z-_@#$%!&*]).{8,20}$";

	@PostConstruct
	public void init() {
		log.info("VonageClient.builder with VONAGE_API_KEY= {} and VONAGE_API_SECRET= {}", VONAGE_API_KEY,
				VONAGE_API_SECRET);
		client = VonageClient.builder().apiKey(VONAGE_API_KEY).apiSecret(VONAGE_API_SECRET).build();
	}

	public ValidateOTPResponse validateOTP(ValidateOTPRequest validateOPTRequest) {
		if (Objects.nonNull(validateOPTRequest.getMobileNumber())) {
			validateOPTRequest.setMobileNumber(validateOPTRequest.getMobileNumber().replace("+", ""));
			ValidateOtpDTO validateOtpDTO = validateOtpRepository
					.findByMobileNumberAndOtpNumber(validateOPTRequest.getMobileNumber(), validateOPTRequest.getOtpCode());
			return validateOTPRequest(validateOPTRequest, validateOtpDTO, MOBILE_VALIDATION );
		} else if(Objects.nonNull(validateOPTRequest.getEmail())) {
			ValidateOtpDTO validateOtpDTO = validateOtpRepository.findByEmailAndOtpNumber(validateOPTRequest.getEmail(), validateOPTRequest.getOtpCode());
			return validateOTPRequest(validateOPTRequest, validateOtpDTO, EMAIL_VALIDATION);
		}
		
		throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "EMAIL_OR_MOBILE_NUMBER_MISSED");
	}
	public ValidateOTPResponse validateOTPRequest(ValidateOTPRequest validateOPTRequest, ValidateOtpDTO validateOtpDTO, String validationType) {
		
		Integer numberOfRetries = 0;
		if (validateOtpDTO != null) {
			numberOfRetries = validateOtpDTO.getNumberOfRetries();
			if (numberOfRetries >= maxNumberOfAttempts && validateOtpDTO.getLastUpdateTime()
					.plusMillis(restMaxNumberOfAttemptsDurationMs).compareTo(Instant.now()) >= 0) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "REACHED_MAX_VERIFICATION_ATTEMPTS");
			}
		} else {
			validateOtpDTO = new ValidateOtpDTO();
			validateOtpDTO.setOtpNumber(validateOPTRequest.getOtpCode());
			if (validationType.equals(MOBILE_VALIDATION)) {
				validateOtpDTO.setMobileNumber(validateOPTRequest.getMobileNumber());
			} else if(validationType.equals(EMAIL_VALIDATION)) {
				validateOtpDTO.setEmail(validateOPTRequest.getEmail());
			}
			validateOtpRepository.insert(validateOtpDTO);
		}

		validateOtpDTO.setLastUpdateTime(Instant.now());
		validateOtpDTO.setNumberOfRetries(numberOfRetries + 1);
		validateOtpRepository.save(validateOtpDTO);

		ValidateOTPResponse validateOTPResponse = new ValidateOTPResponse();
		validateOTPResponse.setValid(validateOTPNumber(validateOPTRequest, validationType));
		return validateOTPResponse;
	}

	public boolean validateOTPNumber(ValidateOTPRequest validateOPTRequest, String validationType) {
		OtpDTO otpData = null;
		if (validationType.equals(MOBILE_VALIDATION)) {
		  otpData = otpDao.getOtpDataByMobileNumber(validateOPTRequest.getMobileNumber());
		} else if(validationType.equals(EMAIL_VALIDATION)) {
		  otpData = otpDao.getOtpDataByEmail(validateOPTRequest.getEmail());
		}
		
		if (otpData != null && otpData.getOtpNumber().equals(validateOPTRequest.getOtpCode())) {
			if (otpData.getExpiryDate().compareTo(Instant.now()) < 0) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "OTP_EXPIRED");
			}
		} else {
			return false;
		}
		return true;
	}

	public void generateAndSend(SendVerificationCodeRequest sendVerificationCode) {
		String otpNumber = String.format("%06d", rnd.nextInt(999999));
		if (Objects.nonNull(sendVerificationCode.getMobileNumber())) {
			generateAndSendViaMobil(sendVerificationCode, otpNumber);
		} else if(Objects.nonNull(sendVerificationCode.getEmail())) {
			generateAndSendViaEmail(sendVerificationCode, otpNumber);
		} else {
			log.error("Send verification code is failed as both email and mobile number are empty");
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "EMAIL_MOBILE_NUMBER_DETAILS_MISSED");
		}
		
	}
	public void generateAndSendViaMobil(SendVerificationCodeRequest sendVerificationCode, String otpNumber) {

		String mobileNumber = sendVerificationCode.getMobileNumber().replace("+", "");
		TextMessage message = new TextMessage(VONAGE_BRAND_NAME, mobileNumber,
				otpNumber + " is your Auth OTP.\nDo not share it with anyone.");

		OtpDTO otpDTOStoredData = otpDao.getOtpDataByMobileNumber(mobileNumber);
		Integer numberOfRetries = 0;
		if (otpDTOStoredData != null) {
			if (otpDTOStoredData.getLastUpdateTime().plusMillis(restMaxNumberOfAttemptsDurationMs)
					.compareTo(Instant.now()) < 0) {
				otpDTOStoredData.setNumberOfRetries(0);
			} else if (otpDTOStoredData.getNumberOfRetries() >= maxNumberOfAttempts) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "REACHED_MAX_VERIFICATION_ATTEMPTS");
			}
			numberOfRetries = otpDTOStoredData.getNumberOfRetries();
		} else {
			otpDTOStoredData = new OtpDTO();
			otpDTOStoredData.setMobileNumber(mobileNumber);
			otpDTOStoredData = otpDao.addNewOtp(otpDTOStoredData);
		}
		otpDTOStoredData.setExpiryDate(Instant.now().plusMillis(otpDTODurationMs));
		otpDTOStoredData.setLastUpdateTime(Instant.now());
		otpDTOStoredData.setNumberOfRetries(numberOfRetries + 1);
		otpDTOStoredData.setOtpNumber(otpNumber);
		otpDao.update(otpDTOStoredData);

		SmsSubmissionResponse response = client.getSmsClient().submitMessage(message);

		if (response.getMessages().get(0).getStatus() == MessageStatus.OK) {
			log.debug("Message sent successfully.");
		} else {
			log.error("Message failed with error: " + response.getMessages().get(0).getErrorText());
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "OTP_FAILED");
		}
	}
	
	public void generateAndSendViaEmail(SendVerificationCodeRequest sendVerificationCode, String otpNumber) {
	
		OtpDTO otpDTOStoredData = otpDao.getOtpDataByEmail(sendVerificationCode.getEmail());
		Integer numberOfRetries = 0;
		if (otpDTOStoredData != null) {
			if (otpDTOStoredData.getLastUpdateTime().plusMillis(restMaxNumberOfAttemptsDurationMs)
					.compareTo(Instant.now()) < 0) {
				otpDTOStoredData.setNumberOfRetries(0);
			} else if (otpDTOStoredData.getNumberOfRetries() >= maxNumberOfAttempts) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "REACHED_MAX_VERIFICATION_ATTEMPTS");
			}
			numberOfRetries = otpDTOStoredData.getNumberOfRetries();
		} else {
			otpDTOStoredData = new OtpDTO();
			otpDTOStoredData.setEmail(sendVerificationCode.getEmail());
			otpDTOStoredData = otpDao.addNewOtp(otpDTOStoredData);
		}
		otpDTOStoredData.setExpiryDate(Instant.now().plusMillis(otpDTODurationMs));
		otpDTOStoredData.setLastUpdateTime(Instant.now());
		otpDTOStoredData.setNumberOfRetries(numberOfRetries + 1);
		otpDTOStoredData.setOtpNumber(otpNumber);
		otpDao.update(otpDTOStoredData);
				
//		sendEmail(sendVerificationCode.getEmail(), otpNumber);

	}
	
//	private void sendEmail(String recipientEmail, String otpNumber) {
//		try {
//			EmailDetails emailDetails = new EmailDetails();
//			List<String> email = new ArrayList<>();
//			email.add(recipientEmail);
//			emailDetails.setRecipients(email);
//			emailDetails.setReplyTo(noReplyEmail);
//			//TO-DO will chnge the url with the correct verify API
//			emailDetails.setHtmlContent(readHtmlFileContent(verificationFilePath, otpNumber));
//			emailDetails.setSubject("Please verify your registration");
//
//			emailUtil.sendEmail(emailDetails);
//		} catch (Exception e) {
//			log.error("Sending email failed due to : {}",e.getMessage());
//		}
//	}

	public static boolean isValidPassword(String password) {
//		Pattern pattern = Pattern.compile(PASS_REGEX);
//		Matcher matcher = pattern.matcher(password);
//		return matcher.matches();
		
		//Temporary solution to support everything and languages.
		return (Objects.nonNull(password)  && 
				!password.trim().isEmpty() &&
				password.length() >= 8     &&
				password.length() <= 20);
	}
	
	public AddNewUserRequest validateAndUpdateBirthdate(AddNewUserRequest addNewUserRequest, DeviceInfo deviceInfo) {
		
		if(Objects.isNull(deviceInfo)) {
			 return addNewUserRequest;
		 }
		 if(Objects.nonNull(deviceInfo.getBirthdate()) && Objects.nonNull(deviceInfo.getDeviceStatus())) {
			if(deviceInfo.getDeviceStatus() == DeviceStatusEnum.VALID) {
				addNewUserRequest.setBirthDate(deviceInfo.getBirthdate());
			} else {
			  log.debug("User/device {} has {} status during the registration", deviceInfo.getDeviceId(), deviceInfo.getDeviceStatus());
			  throw new ResponseStatusException(HttpStatus.FORBIDDEN, deviceInfo.getValidation());
			}
		 }
		 
		 if(!ObjectUtils.isEmpty(deviceInfo.getUserIds())) {
			 if(deviceInfo.getUserIds().size() >= 20) {
				 throw new ResponseStatusException(HttpStatus.FORBIDDEN, "MAX_USERS_PER_DEVICE");
			 }
		 }
		 return addNewUserRequest;
	}
	
	public DeviceInfo updateDeviceInfo(DeviceInfo deviceInfo, AddNewUserRespond respond) {
		if(deviceInfo.getDeviceStatus() == DeviceStatusEnum.VALID) {
			
			deviceInfo.setValidation(AuthConstants.VALID_USER);
			
			List<String> userIds = deviceInfo.getUserIds();
			if(userIds == null) {
				userIds = new ArrayList<>();
			}
			
			userIds.add(respond.getUserId());
			
			deviceInfo.setUserIds(userIds);
		}
		
		return deviceInfo;
	}
	
	public String readHtmlFileContent(String fileName, String otpNumber) throws FileNotFoundException {
		String result = null;
		StringBuilder html = new StringBuilder();
		
		InputStream emailTemplIs = this.getClass().getResourceAsStream(fileName);
		//FileReader reader = new FileReader(fileName);
		try {
			String line = null;
			BufferedReader bReader = new BufferedReader(new InputStreamReader(emailTemplIs, "UTF-8"));
			while ((line = bReader.readLine()) != null) {
				if(line.contains("$code")) {
					line  = line.replace("$code", otpNumber);
				}
				html.append(line + "\n");
			}
			bReader.close();
			result = html.toString();
		} catch (FileNotFoundException e) {
			log.error("File not found :  {}", e);
		} catch (Exception e) {
			log.error("reading html email verification content is failed due to :  {}", e);
		}
		return result;
	}
	
	/**
	 * This method returns number of days between 2 LocalDate objects
	 * 
	 */
	public long getNumberOfDaysBetweenDates(LocalDate fromDate, LocalDate toDate) {
		return Duration.between(fromDate.atStartOfDay(), toDate.atStartOfDay()).toDays();

	}
	
	/**
	 * Check if the requested page is last page.
	 * 
	 */
	public boolean isLastPage(int pageNumber, int pageSize, long totalNumberOfDays) {
		int lastRequiredDayNumber = (pageNumber - 1) * pageSize;
		return totalNumberOfDays - lastRequiredDayNumber < pageSize;
	}
	
	/**
	 * This method creating UserCountDetails object for the dates that don't have
	 * info in DB
	 * 
	 */
	public void appendingZeroCountForNonExistingDateRecords(LocalDate fromDate, LocalDate toDate,
			List<UserCountDetails> userCountList) {

		List<LocalDate> localDateListFromDatabase = userCountList.stream().map(UserCountDetails::getDate)
				.collect(Collectors.toList());

		while (toDate.compareTo(fromDate) >= 0) {
			if (!localDateListFromDatabase.contains(fromDate)) {
				UserCountDetails userCountDetails = new UserCountDetails();
				userCountDetails.setCount(0);
				userCountDetails.setDate(fromDate);
				userCountList.add(userCountDetails);
			}
			fromDate = fromDate.plusDays(1);
			userCountList.sort(Comparator.comparing(UserCountDetails::getDate));
		}
	}
}