package com.social.auth.consts;

public interface AuthConstants {
	
	String DEVICE_INFO = "device_info";
	String BIRTH_DATE = "birthdate";
	String LAST_TRY_DATE = "lastTryDate";
	String VALIDATION = "validation";
	String DEVICE_STATUS = "deviceStatus";
	String VALID_USER = "VALID_USER";
	
	String UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS";
	String USER_NOT_FOUND = "USER_NOT_FOUND";
	
	String ACCEPTED = "Accepted";
	String REJECTED = "Rejected";
	
    String DEVICE_ID = "deviceId";
    String UNDERAGE = "UNDERAGE";
    String VALID_AGE = "VALID_AGE";
    String BLOCKED_BY_APP = "BLOCKED_BY_APP";
	
	int AGE_LIMIT = 13;
	
	String EMAIL_VALIDATION = "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@[^-][A-Za-z0-9-]+(\\.[A-Za-z09-]+)*(\\.[A-Za-z]{2,})$";
	String MOBILE_VALIDATION = "^[\\+]?[(]?[0-9]{3}[)]?[-\\s\\.]?[0-9]{3}[-\\s\\.]?[0-9]{4,14}$";
}
