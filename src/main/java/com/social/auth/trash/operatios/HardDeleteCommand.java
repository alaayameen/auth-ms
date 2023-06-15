package com.social.auth.trash.operatios;

import com.social.auth.trash.service.TrashService;
import com.social.auth.trash.utils.Constants;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @author ayameen
 *
 */
@Service
@Log4j2
public class HardDeleteCommand extends Command {

    @Autowired
    TrashService trashService;

    @Override
    public void execute(Constants.ID_TYPE idType) {
        log.debug("Execute Command: {}, ID Type: {}, Id: {}, Report Id: {}", contentManagementRequest.getContentCommand(),
                idType, contentManagementRequest.getId(), contentManagementRequest.getReportId());
        if (idType == Constants.ID_TYPE.USER_ID) {
            trashService.hardDeleteByUserId(contentManagementRequest.getId());
        }
    }
}
