package com.social.auth.trash.mapper;

import com.social.auth.data.mongo.models.RefreshToken;
import com.social.auth.trash.enums.ContentCommand;
import com.social.auth.trash.model.Trash;
import com.social.auth.trash.utils.SerializationHandler;
import com.social.auth.trash.utils.Constants;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * @author ayameen
 */
@AllArgsConstructor
@Service
public class TrashedRefreshTokenMapper {

    SerializationHandler serializationHandler;

    public Trash toTrash(RefreshToken refreshToken, String command, String parentId) {
        return Trash.builder()
                .command(ContentCommand.fromValue(command))
                .deletedDate(LocalDateTime.now())
                .classForName(refreshToken.getClass().getName())
                .entityId(refreshToken.getId())
                .entityName(Constants.CONTENT_TYPE.REFRESH_TOKEN.name())
                .parentId(parentId)
                .serializedEntity(serializationHandler.serializeEntity(refreshToken))
                .build();
    }

    public RefreshToken toRefreshTokenView(Trash trash) {
        return (RefreshToken) serializationHandler.deSerializeEntity(trash.getSerializedEntity(), trash.getClassForName());
    }
}
