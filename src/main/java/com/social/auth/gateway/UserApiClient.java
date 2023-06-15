package com.social.auth.gateway;

import com.social.swagger.called.user.api.UserApi;
import org.springframework.stereotype.Service;

import com.social.swagger.called.user.api.AdminUserApi;
import com.social.swagger.called.user.model.AddNewUserRequest;
import com.social.swagger.called.user.model.AddNewUserRespond;
import com.social.swagger.called.user.model.UpdateUserRequest;
import com.social.swagger.called.user.model.UserInfoForAdmin;
import com.social.swagger.called.user.restclient.ApiClient;

import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Service
@AllArgsConstructor
@Log4j2
public class UserApiClient {

    private com.social.core.utils.commonUtils commonUtils;
    private ApiClient apiClient;
    private UserApi userApi;
    AdminUserApi adminUserApi;

    public AddNewUserRespond addNewUser(String authorization, AddNewUserRequest addNewUserRequest) {
        log.debug("addNewUser called with addNewUserRequest {}", addNewUserRequest);
        apiClient.setBasePath(commonUtils.buildUrl("user-ms", apiClient.getBasePath()).toString());
        apiClient.setUserAgent("auth-ms");
        userApi.setApiClient(apiClient);
        return userApi.addNewUser(authorization, addNewUserRequest);
    }
    public void updateUser(String authorization, UpdateUserRequest updateUserRequest) {
        log.debug("updateUser called with updateUserRequest {}", updateUserRequest);
        apiClient.setBasePath(commonUtils.buildUrl("user-ms", apiClient.getBasePath()).toString());
        apiClient.setUserAgent("auth-ms");
        userApi.setApiClient(apiClient);
        userApi.updateUser(authorization, updateUserRequest);
    }

    public UserInfoForAdmin getUserStatusDetailByAdmin(String authorization, String userId) {
        log.debug("getUserDetails called");
        apiClient.setBasePath(commonUtils.buildUrl("user-ms", apiClient.getBasePath()).toString());
        adminUserApi.setApiClient(apiClient);
        return adminUserApi.getUserStatusDetailByAdmin(authorization, userId);
    }
    
    public UserInfoForAdmin getUserDetailByUsername(String authorization, String username) {
        log.debug("getUserDetails called");
        apiClient.setBasePath(commonUtils.buildUrl("user-ms", apiClient.getBasePath()).toString());
        adminUserApi.setApiClient(apiClient);
        return adminUserApi.getUserDetailByUsername(authorization, username);
    }

    public void rollbackUserDeleteStatus(String authorization, String userId) {
        log.debug("rollbackUserDeleteStatus called");
        apiClient.setBasePath(commonUtils.buildUrl("user-ms", apiClient.getBasePath()).toString());
        adminUserApi.setApiClient(apiClient);
        adminUserApi.rollbackUserDeleteStatus(authorization, userId);
    }
}
