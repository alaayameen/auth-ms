package com.social.auth.data.mongo.dao;

import com.social.auth.data.mongo.models.OtpDTO;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OtpRepository extends MongoRepository<OtpDTO, String> {
    OtpDTO findByMobileNumber(String mobileNumber);
    OtpDTO findByEmail(String email);
    void deleteByMobileNumber(List<String> mobileNumbers);

}
