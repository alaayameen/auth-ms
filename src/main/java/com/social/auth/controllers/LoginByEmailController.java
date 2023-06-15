package com.social.auth.controllers;


import com.social.auth.data.mongo.dao.AuthDao;
import com.social.auth.data.mongo.models.Auth;
import com.social.auth.gateway.UserApiClient;
import com.social.auth.services.RefreshTokenService;
import com.social.swagger.called.user.model.UserInfoForAdmin;
import com.social.swagger.model.auth.AuthenticateRespond;
import com.social.core.models.RuleEnum;
import com.social.core.models.UsedLoginEnum;
import com.social.core.models.UserInfo;
import com.social.core.utils.JWTUtil;
import com.social.swagger.model.auth.LoginByEmail;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;

@Log4j2
@Controller
@AllArgsConstructor
public class LoginByEmailController {
	private JWTUtil jwtUtil;
	private AuthDao authDao;
	private final RefreshTokenService refreshTokenService;
	private PasswordEncoder passwordEncoder;
	UserApiClient userApiClient;

	public AuthenticateRespond loginByEmail(LoginByEmail loginByEmailRequest, String acceptLanguage) {
		log.debug("loginByEmail called with request {}", loginByEmailRequest);
		Auth authData = authDao.getAuthDataByEmail(loginByEmailRequest.getEmail());

		log.debug("loginByEmail authData {}", authData);
		if (authData != null) {
			if (passwordEncoder.matches(loginByEmailRequest.getPassword(), authData.getPassword())) {
				String adminToken = "Bearer " + jwtUtil.generateTokenForAdminUser();

				UserInfoForAdmin userInfoForAdmin = userApiClient.getUserStatusDetailByAdmin(adminToken,
						authData.getUserId());
				log.debug("loginByEmail userInfo {}", userInfoForAdmin);

				if (userInfoForAdmin != null) {
					if (Boolean.TRUE.equals(userInfoForAdmin.isIsDeleted())) {
						throw new ResponseStatusException(HttpStatus.FORBIDDEN, "DELETED_USER");
					}

					if (Boolean.FALSE.equals(userInfoForAdmin.isActive())) {
						throw new ResponseStatusException(HttpStatus.FORBIDDEN, "USER_IS_DEACTIVATED");
					}

					if (Boolean.TRUE.equals(userInfoForAdmin.isMarkedForDelete())) {
						if (Boolean.TRUE.equals(loginByEmailRequest.isRestoreAccount())) {
							if (userInfoForAdmin.getCanRollbackDeleteDate() != null
									&& LocalDate.now().isBefore(userInfoForAdmin.getCanRollbackDeleteDate())) {
								userInfoForAdmin.setMarkedForDelete(false);
								userApiClient.rollbackUserDeleteStatus(adminToken, authData.getUserId());
							} else {
								throw new ResponseStatusException(HttpStatus.FORBIDDEN,
										"CANNOT_RESTORE_DELETED_ACCOUNT");
							}
						} else {
							if (userInfoForAdmin.getCanRollbackDeleteDate() != null
									&& LocalDate.now().isBefore(userInfoForAdmin.getCanRollbackDeleteDate())) {
								throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ACCOUNT_MARKED_FOR_DELETE");
							} else {
								throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ACCOUNT_IS_DELETED");
							}
						}
					}
				}

				AuthenticateRespond authenticateRespond = new AuthenticateRespond();
				authenticateRespond.setAccessToken(generateTokenFromUserInfo(loginByEmailRequest, loginByEmailRequest.getEmail(),
						authData.getUserId(), null, authData.getRule(), userInfoForAdmin));
				authenticateRespond
						.setRefreshToken(refreshTokenService.createRefreshToken(authData.getId()).getToken());

				log.debug("loginByEmail token are generated {}", authenticateRespond);
				return authenticateRespond;
			} else {
				throw new ResponseStatusException(HttpStatus.FORBIDDEN, "WRONG_EMAIL_PASSWORD");
			}
		}
		throw new ResponseStatusException(HttpStatus.NOT_FOUND, "USER_NOT_FOUND");
	}
	
	private String generateTokenFromUserInfo(LoginByEmail loginByEmailRequest, String email, String userId, String acceptLanguage, RuleEnum ruleEnum, UserInfoForAdmin userInfoForAdmin) {
        UserInfo userInfo;

        userInfo = new UserInfo();
        userInfo.setId(userId);
        userInfo.setEmail(email);
        userInfo.setUsedLoginEnum(UsedLoginEnum.EMAIL);
        if (userInfoForAdmin != null) {
            userInfo.setIsActive(userInfoForAdmin.isActive());
            userInfo.setIsDeleted(userInfoForAdmin.isIsDeleted());
            userInfo.setUserName(userInfoForAdmin.getUserName());
            userInfo.setNumericUserId(userInfoForAdmin.getNumericUserId());
        }

        if(acceptLanguage != null && !"".equals(acceptLanguage)) {
        }
        userInfo.setRule(ruleEnum);
        return jwtUtil.generateTokenFromUserInfo(userInfo);
    }

}