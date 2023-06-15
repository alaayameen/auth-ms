package com.social.auth.data.mongo.models;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import com.social.auth.consts.AuthConstants;

import lombok.Data;

import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@NoArgsConstructor
@Data
@Document(collection = AuthConstants.DEVICE_INFO)
public class DeviceInfo implements AuthConstants{
	@Id
	private String id;
	
	@Indexed(unique = true)
	private String deviceId;
	private List<String> userIds;
	
	@CreatedDate
	private LocalDateTime createdAt;
	
	@Field(BIRTH_DATE)
	private LocalDate birthdate;
	
	@LastModifiedDate
	private LocalDateTime updatedAt;
	
	@Field(LAST_TRY_DATE)
	private LocalDateTime lastTryDate;
	private DeviceStatusEnum deviceStatus;
	private String validation;
	
}
