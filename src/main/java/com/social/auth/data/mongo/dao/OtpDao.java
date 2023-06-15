package com.social.auth.data.mongo.dao;

import com.social.auth.data.mongo.models.OtpDTO;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;

@Log4j2
@Component
@AllArgsConstructor
public class OtpDao {
    private final OtpRepository otpRepository;
    
    public OtpDTO getOtpDataByMobileNumber(String mobileNumber){
        return otpRepository.findByMobileNumber(mobileNumber);
    }
    
    public OtpDTO getOtpDataByEmail(String email){
        return otpRepository.findByEmail(email);
    }

    public OtpDTO update(OtpDTO otpDTOStoredData) {
        return otpRepository.save(otpDTOStoredData);
    }

    public OtpDTO addNewOtp(OtpDTO otpDTO) {
        return otpRepository.insert(otpDTO);
    }
}
