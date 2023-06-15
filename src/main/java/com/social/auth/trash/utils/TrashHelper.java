package com.social.auth.trash.utils;

import com.social.auth.trash.TrashedDataProperties;
import com.social.auth.trash.enums.ContentCommand;
import com.social.core.utils.JWTUtil;
import com.social.swagger.model.contentmanagement.ContentManagementRequest;
import lombok.AllArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;

/**
 * @author ayameen
 *
 */
@Log4j2
@AllArgsConstructor
@Component
public class TrashHelper {

	JWTUtil jwtUtil;

	TrashedDataProperties trashedDataProperties;

	public int getExpireAtInDays() {
		int deleteInDays;
		try {
			deleteInDays = Integer.parseInt(trashedDataProperties.getExpireAtInDays());
		} catch (Exception e) {
			deleteInDays = 30;
		}
		return deleteInDays;
	}

	public ContentCommand getDeleteCommand(ContentManagementRequest.ContentCommandEnum contentCommand) {
		switch (contentCommand) {
			case DIRECT_ADMIN_RESTORE_CONTENT:
				return ContentCommand.DIRECT_ADMIN_SOFT_DELETE;
			case REPORT_RESTORE_DELETE:
				return ContentCommand.REPORT_SOFT_DELETE;
			case DELETE_ACCOUNT_RESTORE_CONTENT:
				return ContentCommand.DELETE_ACCOUNT_SOFT_DELETE;
			case UN_BAN_ACCOUNT:
				return ContentCommand.BAN_ACCOUNT;
			default:
				return null;
		}
	}
}
