package com.social.auth.trash.dao;

import com.social.auth.trash.model.Trash;
import lombok.AllArgsConstructor;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.index.Index;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.List;


@Component
@AllArgsConstructor
public class TrashDao {

    MongoTemplate mongoTemplate;

    TrashRepository trashRepository;


    public List<Trash> findByEntityIdInAndCommandAndEntityName(List<String> ids, String command, String entityName) {
        return trashRepository.findByEntityIdInAndCommandAndEntityName(ids, command, entityName);
    }

    public List<Trash> findByParentIdInAndCommandAndEntityName(List<String> ids, String command, String entityName) {
        return trashRepository.findByParentIdInAndCommandAndEntityName(ids, command, entityName);
    }

    public void saveAll(List<Trash> trashedPosts) {
        trashRepository.saveAll(trashedPosts);
    }

    public List<Trash> findByUserIdAndCommandAndEntityName(String userId, String command, String entityName) {
        return trashRepository.findByUserIdAndCommandAndEntityName(userId, command, entityName);
    }

    public void deleteAll(List<Trash> trashedPosts) {
        trashRepository.deleteAll(trashedPosts);
    }

    /**
     * This index will delete documents when expireAt datetime is passed, automatically handled by mongod thread
     */
    @PostConstruct
    private void createExpireAtIndex() {

        Index expireAtIndex = new Index()
                .background()
                .named("expire_at_index")
                .on("expireAt", Sort.Direction.ASC)
                .expire(0);

        mongoTemplate.indexOps("trash").ensureIndex(expireAtIndex);
    }
}

