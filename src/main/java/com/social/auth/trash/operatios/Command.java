package com.social.auth.trash.operatios;


import com.social.auth.trash.utils.Constants;
import com.social.swagger.model.contentmanagement.ContentManagementRequest;

/**
 * @author ayameen
 */
public abstract class Command {
    ContentManagementRequest contentManagementRequest;
    String contentType;
    String authorization;

    abstract void execute(Constants.ID_TYPE idType);

    public ContentManagementRequest getContentManagementRequest() {
        return contentManagementRequest;
    }

    public Command setContentManagementRequest(ContentManagementRequest contentManagementRequest) {
        this.contentManagementRequest = contentManagementRequest;
        return this;
    }

    public String getContentType() {
        return contentType;
    }

    public Command setContentType(String contentType) {
        this.contentType = contentType;
        return this;
    }

    public String getAuthorization() {
        return authorization;
    }

    public Command setAuthorization(String authorization) {
        this.authorization = authorization;
        return this;
    }
}
