package com.social.auth.data.mongo.dao;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import org.springframework.data.mongodb.repository.Aggregation;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.social.auth.data.mongo.models.DeviceInfo;
import com.social.auth.data.mongo.models.DeviceStatusEnum;
import com.social.swagger.model.auth.UserCountDetails;

@Repository
public interface DeviceInfoRepository extends MongoRepository<DeviceInfo , String> {
	Optional<DeviceInfo> findByDeviceId(String deviceId);
	List<DeviceInfo> findByValidationOrDeviceStatus(String validation, DeviceStatusEnum status);
	void deleteByDeviceId(String deviceId);
	
	@Aggregation(pipeline = { "{$match: { 'createdAt': { $gte : ?1,  $lte : ?2} }},",
			"{$project: {_id: 0, onlyDate: { $dateToString: {format: '%Y-%m-%d', date: '$createdAt' }}, _id: '$_id'}},",
			"{$group: {_id:{ onlyDate: '$onlyDate'},count:{ '$sum': 1 }}}",
			"{$project: {_id: 0, date: '$_id.onlyDate', count: '$count'}}", "{$sort: {'date': -1}}",
			"{ $skip: ?3}", "{ $limit: ?4}" })
	public List<UserCountDetails> getNewUsersCount(String authorization, LocalDate fromDate, LocalDate toDate, int skip, int limit);
		
	    
}
