package com.social.auth.data.mongo.dao;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.mongodb.core.BulkOperations;
import org.springframework.data.mongodb.core.BulkOperations.BulkMode;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import com.social.auth.consts.AuthConstants;
import com.social.auth.data.mongo.models.DeviceInfo;
import com.social.auth.data.mongo.models.DeviceStatusEnum;
import com.social.swagger.model.auth.UserCountDetails;

import org.springframework.data.mongodb.core.query.Query;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Log4j2
@Component
@AllArgsConstructor
public class DeviceInfoDao implements AuthConstants{
	private final DeviceInfoRepository deviceInfoRepository;
	private MongoTemplate mongoTemplate;
	
	public DeviceInfo saveDeviceInfo(DeviceInfo deviceInfo) {
		try {
			log.debug("Saving new auth device/user Info {}",deviceInfo);
			return deviceInfoRepository.save(deviceInfo);
			
		} catch (Exception e) {
			log.error("MONGO_DB_SAVE_AUTH_USER_INFO_FAILED while saving device Id {} due to {}", deviceInfo.getDeviceId(), e.getMessage());
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "MONGO_DB_SAVE_AUTH_USER_INFO_FAILED");
		} 
	}
	
	public void updateDeviceInfo(DeviceInfo deviceInfo){
		Update deviceInfoUpdate = new Update();
		deviceInfoUpdate.set(BIRTH_DATE, deviceInfo.getBirthdate());
		mongoTemplate.upsert(
				Query.query(Criteria.where(DEVICE_ID).is(deviceInfo.getDeviceId())), 
				deviceInfoUpdate,
				DeviceInfo.class
				).wasAcknowledged();
	}
	
	public void updateDeviceInfoStatusDetails(DeviceInfo deviceInfo){
		Update deviceInfoUpdate = new Update();
		deviceInfoUpdate.set(DEVICE_STATUS, deviceInfo.getDeviceStatus());
		deviceInfoUpdate.set(VALIDATION, deviceInfo.getValidation());
		mongoTemplate.upsert(
				Query.query(Criteria.where(DEVICE_ID).is(deviceInfo.getDeviceId())), 
				deviceInfoUpdate,
				DeviceInfo.class
				).wasAcknowledged();
	}
	
	public boolean UnblockDevices(List<String> devicesIds) {
		try {
			BulkOperations bulkOps = mongoTemplate.bulkOps(BulkMode.UNORDERED, DeviceInfo.class);
			
			for (String deviceId : devicesIds) {
				Query query = Query.query(Criteria.where(DEVICE_ID).is(deviceId));
			    Update update = new Update()
			    		.set(VALIDATION, VALID_USER )
			    		.set(DEVICE_STATUS, DeviceStatusEnum.VALID.toString());
			    bulkOps.updateOne(query, update);
			}
			
			return bulkOps.execute().wasAcknowledged();
		} catch (Exception e) {
			log.error("MONGO_DB_UPDATE_DEVICE_INFO_FAILED while updating device info due to {}", e.getMessage());
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "MONGO_DB_UPDATE_DEVICE_INFO_FAILED");
		}	
	}
	public void updateLastTryDate(DeviceInfo deviceInfo){
		Update deviceInfoUpdate = new Update();
		deviceInfoUpdate.set(LAST_TRY_DATE, LocalDateTime.now());
		
		mongoTemplate.upsert(
				Query.query(Criteria.where(DEVICE_ID).is(deviceInfo.getDeviceId())), 
				deviceInfoUpdate,
				DeviceInfo.class
				).wasAcknowledged();
	}
	
	
	public Optional<DeviceInfo> getDeviceInfoByDeviceId(String deviceId){
		return deviceInfoRepository.findByDeviceId(deviceId);
	}
	
	public List<DeviceInfo> getDeviceInfoByValidationOrUserStatus(String validation, DeviceStatusEnum userStatus){
		return deviceInfoRepository.findByValidationOrDeviceStatus(validation, userStatus);
	}
	
	public void deleteByDeviceId(String deviceId){
		deviceInfoRepository.deleteByDeviceId(deviceId);
	}
	
	public List<UserCountDetails> getNewUsersCount(String authorization, LocalDate fromDate, LocalDate toDate, int skip, int limit){
		return deviceInfoRepository.getNewUsersCount(authorization, fromDate, toDate, skip, limit);
	}
	
}
