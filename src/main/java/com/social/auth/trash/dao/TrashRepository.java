package com.social.auth.trash.dao;

import com.social.auth.trash.model.Trash;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.List;


/**
 * @author ayameen
 *
 */
@Repository
public interface TrashRepository extends MongoRepository<Trash, String> {
    List<Trash> findByUserIdAndCommandAndEntityName(String userId, String command, String entityName);
    List<Trash> findByEntityIdInAndCommandAndEntityName(List<String> ids, String command, String entityName);
    List<Trash> findByParentIdInAndCommandAndEntityName(List<String> ids, String command, String entityName);
}
