package com.social.auth.trash.operatios;


import com.social.auth.data.mongo.dao.AuthDao;
import com.social.auth.trash.service.TrashService;
import com.social.auth.trash.utils.Constants;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author ayameen
 *
 */
@Service
@Log4j2
public class BanUserCommand extends Command {

    @Autowired
    AuthDao authDao;

    @Autowired
    TrashService trashService;

    @Override
    public void execute(Constants.ID_TYPE idType) {
        log.debug("Execute Command: {}, ID Type: {}, Id: {}, Report Id: {}", contentManagementRequest.getContentCommand(),
                idType, contentManagementRequest.getId(), contentManagementRequest.getReportId());
        if (idType.equals(Constants.ID_TYPE.USER_ID)) {
            banUsersContent();
        }
    }

    void banUsersContent() {
        List<String> authIds = authDao.findIdByUserId(contentManagementRequest.getId());
        trashService.softDeleteAuths(authIds, contentManagementRequest.getReportId(), contentManagementRequest.getContentCommand().name());
    }
}
