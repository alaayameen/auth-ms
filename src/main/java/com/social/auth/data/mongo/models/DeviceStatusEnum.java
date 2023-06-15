package com.social.auth.data.mongo.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum DeviceStatusEnum {
	VALID("VALID"),
	    
	INVALID("INVALID"),

	BLOCKED("BLOCKED");

	private String value;

	DeviceStatusEnum(String value) {
		this.value = value;
	}

	@Override
	@JsonValue
	public String toString() {
		return String.valueOf(value);
	}

	@JsonCreator
	public static DeviceStatusEnum fromValue(String text) {
		for (DeviceStatusEnum b : DeviceStatusEnum.values()) {
			if (String.valueOf(b.value).equals(text)) {
				return b;
	        }
	    }
	    return null;
	}
}
