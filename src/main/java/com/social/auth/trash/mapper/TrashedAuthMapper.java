package com.social.auth.trash.mapper;

import com.social.auth.trash.enums.ContentCommand;
import com.social.auth.trash.utils.SerializationHandler;
import com.social.auth.data.mongo.models.Auth;
import com.social.auth.trash.model.Trash;
import com.social.auth.trash.utils.Constants;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author ayameen
 */
@AllArgsConstructor
@Service
public class TrashedAuthMapper {

    SerializationHandler serializationHandler;

    public Trash toTrash(Auth auth, String command) {
        return Trash.builder()
                .command(ContentCommand.fromValue(command))
                .deletedDate(LocalDateTime.now())
                .classForName(auth.getClass().getName())
                .entityId(auth.getId())
                .entityName(Constants.CONTENT_TYPE.AUTH.name())
                .userId(auth.getUserId())
                .serializedEntity(serializationHandler.serializeEntity(auth))
                .build();
    }

    public List<Trash> toTrashes(List<Auth> auths, String command) {
        return auths.stream().map(story -> toTrash(story, command)).collect(Collectors.toList());
    }

    public Auth toAuth(Trash trash) {
        return (Auth) serializationHandler.deSerializeEntity(trash.getSerializedEntity(), trash.getClassForName());
    }
}
