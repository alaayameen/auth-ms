package com.social.auth.trash.operatios;

import com.social.auth.trash.dao.TrashDao;
import com.social.auth.trash.model.Trash;
import com.social.auth.trash.service.TrashService;
import com.social.auth.trash.utils.Constants;
import com.social.auth.trash.utils.TrashHelper;
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
public class UnBanUserCommand extends Command {

    @Autowired
    TrashDao trashDao;

    @Autowired
    TrashService trashService;

    @Autowired
    TrashHelper helper;

    @Override
    public void execute(Constants.ID_TYPE idType) {
        log.debug("Execute Command: {}, ID Type: {}, Id: {}, Report Id: {}", contentManagementRequest.getContentCommand(),
                idType, contentManagementRequest.getId(), contentManagementRequest.getReportId());
        if (idType.equals(Constants.ID_TYPE.USER_ID)) {
            restoreByUserId();
        }
    }

    void restoreByUserId() {
        String deleteCommand = helper.getDeleteCommand(contentManagementRequest.getContentCommand()).name();
        List<Trash> trashedList = trashDao.findByUserIdAndCommandAndEntityName(contentManagementRequest.getId(), deleteCommand, Constants.CONTENT_TYPE.AUTH.name());
        trashService.restoreTrashedAuths(trashedList, deleteCommand, authorization);
    }
}
