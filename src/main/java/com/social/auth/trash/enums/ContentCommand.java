package com.social.auth.trash.enums;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * @author ayameen
 *
 */
public enum ContentCommand {
	DIRECT_ADMIN_SOFT_DELETE("DIRECT_ADMIN_SOFT_DELETE"),
	DIRECT_ADMIN_RESTORE_CONTENT("DIRECT_ADMIN_RESTORE_CONTENT"),
	DIRECT_ADMIN_HARD_DELETE("DIRECT_ADMIN_HARD_DELETE"),

	REPORT_SOFT_DELETE("REPORT_SOFT_DELETE"),
	REPORT_RESTORE_DELETE("REPORT_RESTORE_DELETE"),
	REPORT_HARD_DELETE("REPORT_HARD_DELETE"),

	DELETE_ACCOUNT_SOFT_DELETE("DELETE_ACCOUNT_SOFT_DELETE"),
	DELETE_ACCOUNT_RESTORE_CONTENT("DELETE_ACCOUNT_RESTORE_CONTENT"),

	BAN_ACCOUNT("BAN_ACCOUNT"),
	UN_BAN_ACCOUNT("UN_BAN_ACCOUNT");

	private final String value;

	private ContentCommand(String value) {
		this.value = value;
	}

	@Override
	@JsonValue
	public String toString() {
		return value;
	}

	@JsonCreator
	public static ContentCommand fromValue(String text) {
		return ContentCommand.valueOf(text);
	}
}
