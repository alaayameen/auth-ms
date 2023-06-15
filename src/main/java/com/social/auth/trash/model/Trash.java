package com.social.auth.trash.model;

import com.social.auth.trash.enums.ContentCommand;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

/**
 * @author ayameen
 */
@Getter
@Setter
@SuperBuilder
@Document("trash")
@NoArgsConstructor
public class Trash {
    @Id
    private String id;

    @Indexed
    private String parentId;

    @Indexed
    private String entityName;

    @Indexed
    private String userId;

    @Indexed
    private String entityId;
    private String classForName;
    private String serializedEntity;
    private String deletedBy;
    private LocalDateTime deletedDate;

    @Indexed
    private ContentCommand command;
    private String reportingId;
    private LocalDateTime expireAt;
}
