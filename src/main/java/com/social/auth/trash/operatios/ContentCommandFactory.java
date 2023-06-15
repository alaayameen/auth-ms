package com.social.auth.trash.operatios;

import com.social.swagger.model.contentmanagement.ContentManagementRequest;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class ContentCommandFactory {

    private final SoftDeleteCommand softDeleteCommand;
    private final RestoreDeleteCommand restoreDeleteCommand;
    private final HardDeleteCommand hardDeleteCommand;
    private final BanUserCommand banUserCommand;
    private final UnBanUserCommand unBanUserCommand;

    public Command getCommentCommand(ContentManagementRequest contentManagementRequest, String contentType, String authorization){
        switch (contentManagementRequest.getContentCommand()) {
            case DIRECT_ADMIN_HARD_DELETE:
            case REPORT_HARD_DELETE:
                return hardDeleteCommand
                        .setContentManagementRequest(contentManagementRequest)
                        .setAuthorization(authorization)
                        .setContentType(contentType);
            case DIRECT_ADMIN_SOFT_DELETE:
            case REPORT_SOFT_DELETE:
            case DELETE_ACCOUNT_SOFT_DELETE:
                return softDeleteCommand
                        .setContentManagementRequest(contentManagementRequest)
                        .setAuthorization(authorization)
                        .setContentType(contentType);
            case DIRECT_ADMIN_RESTORE_CONTENT:
            case REPORT_RESTORE_DELETE:
            case DELETE_ACCOUNT_RESTORE_CONTENT:
                return restoreDeleteCommand
                        .setContentManagementRequest(contentManagementRequest)
                        .setAuthorization(authorization)
                        .setContentType(contentType);
            case BAN_ACCOUNT:
                return banUserCommand
                        .setContentManagementRequest(contentManagementRequest)
                        .setAuthorization(authorization)
                        .setContentType(contentType);
            case UN_BAN_ACCOUNT:
                return unBanUserCommand
                        .setContentManagementRequest(contentManagementRequest)
                        .setAuthorization(authorization)
                        .setContentType(contentType);
            default:
                return null;
        }
    }
}
