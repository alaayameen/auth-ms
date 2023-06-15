package com.social.auth.data.mongo.dao;

import com.social.auth.data.mongo.models.ValidateOtpDTO;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ValidateOtpRepository extends MongoRepository<ValidateOtpDTO,String> {
    ValidateOtpDTO findByMobileNumberAndOtpNumber(String mobileNumber, String otpNumber);
    ValidateOtpDTO findByEmailAndOtpNumber(String email, String otpNumber);
    void deleteByMobileNumber(List<String> mobileNumbers);
}
