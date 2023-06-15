package com.social.auth.trash.utils;

/**
 * @author ayameen
 *
 */
public interface Constants {

	int FETCH_BATCH_SIZE = 100;

	enum ID_TYPE {
		USER_ID("USER_ID");

		private final String value;

		ID_TYPE(String value) {
			this.value = value;
		}

		public String getValue() {
			return value;
		}
	}

	enum CONTENT_TYPE {
		AUTH("AUTH"),
		REFRESH_TOKEN("REFRESH_TOKEN");
        private final String value;

		CONTENT_TYPE(String value) {
			this.value = value;
		}

		public String getValue() {
			return value;
		}
	}

}
