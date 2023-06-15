package com.social.auth.trash;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * @author ayameen
 *
 */
@Data
@Component
@ConfigurationProperties(prefix = "trash")
public class TrashedDataProperties {
	private String expireAtInDays;
}
