package com.social.auth.trash.service;


import com.social.swagger.model.contentmanagement.ContentManagementRequest;

public interface ContentManagementService {

    /**
     * Take an action (soft delete, restore, hard delete, ban, un ban), action sources(direct by admin, report, delete account)
     * on content(Post, story, video, comment, reply and user) by content id list
     *
     * @param authorization logged in user
     * @param contentManagementRequest request body
     */
    void manageContentById(String authorization, ContentManagementRequest contentManagementRequest);
}
