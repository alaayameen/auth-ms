package com.social.auth.trash.service;


import com.social.auth.trash.model.Trash;

import java.util.List;

public interface TrashService {
    void softDeleteAuths(List<String> authIds, String reportId, String name);

    void restoreTrashedAuths(List<Trash> trashes, String deleteCommand, String authorization);

    void hardDeleteByUserId(String id);
}
