package com.social.auth.trash.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;

/**
 * @author ayameen
 *
 */
@Log4j2
@AllArgsConstructor
@Component
public class SerializationHandler {

	private final ObjectMapper objectMapper;

	@SneakyThrows
	public String serializeEntity(Object entity) {
		if (!objectMapper.canSerialize(entity.getClass())) { throw new AssertionError(); }
		return objectMapper.writeValueAsString(entity);
	}

	@SneakyThrows
	public Object deSerializeEntity(String entity, String className) {
		Class<?> classType = Class.forName(className);
		return objectMapper.readValue(entity, classType);
	}
}
