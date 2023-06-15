package com.social.auth.trash.service.impl;

import com.social.auth.data.mongo.dao.AuthDao;
import com.social.auth.data.mongo.models.Auth;
import com.social.auth.data.mongo.models.RefreshToken;
import com.social.auth.trash.enums.ContentCommand;
import com.social.auth.trash.mapper.TrashedAuthMapper;
import com.social.auth.trash.model.Trash;
import com.social.auth.trash.service.TrashService;
import com.social.auth.trash.utils.TrashHelper;
import com.google.common.collect.Lists;
import com.social.auth.data.mongo.dao.RefreshTokenDao;
import com.social.core.models.UserInfo;
import com.social.auth.trash.dao.TrashDao;
import com.social.auth.trash.mapper.TrashedRefreshTokenMapper;
import com.social.auth.trash.utils.Constants;
import com.social.core.utils.JWTUtil;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author ayameen
 */
@Service
@AllArgsConstructor
public class TrashServiceImpl implements TrashService {

    AuthDao authDao;
    RefreshTokenDao refreshTokenDao;
    TrashDao trashDao;
    TrashedAuthMapper trashedAuthMapper;
    TrashHelper trashHelper;
    TrashedRefreshTokenMapper trashedRefreshTokenMapper;
    JWTUtil jwtUtil;

    @Override
    public void softDeleteAuths(List<String> authIds, String reportId, String command) {
        UserInfo userInfo = jwtUtil.getUserInfoFromToken();
        List<List<String>> chunks = Lists.partition(authIds, Constants.FETCH_BATCH_SIZE);
        chunks.forEach(chunk -> {
            List<Auth> auths = authDao.findByIdIn(chunk);
            deleteAuthViewByAuthIds(chunk, command, reportId, userInfo.getId());

            List<Trash> trashes = auths.stream().map(auth -> {
                Trash trash = trashedAuthMapper.toTrash(auth, command);
                trash.setReportingId(reportId);
                trash.setDeletedBy(userInfo.getId());
                return trash;
            }).collect(Collectors.toList());

            populateExpireAt(trashes, command, trashHelper.getExpireAtInDays());
            trashDao.saveAll(trashes);
            authDao.deleteAll(auths);
        });
    }

    @Override
    public void restoreTrashedAuths(List<Trash> trashes, String deleteCommand, String authorization) {
        if (trashes == null || trashes.isEmpty()) {
            return;
        }

        List<List<Trash>> chunks = Lists.partition(trashes, Constants.FETCH_BATCH_SIZE);
        chunks.forEach(chunk -> {
            List<String> authIds =  chunk.stream().map(Trash::getEntityId).collect(Collectors.toList());
            restoreAuthViewByIds(authIds, deleteCommand);
            List<Auth> stories = chunk.stream().map(trash -> trashedAuthMapper.toAuth(trash)).collect(Collectors.toList());
            authDao.insertAllIgnoreAuditing(stories);
            trashDao.deleteAll(chunk);
        });
    }

    public void restoreAuthViewByIds(List<String> authIds, String deletedCommand) {
        List<List<String>> chunks = Lists.partition(authIds, Constants.FETCH_BATCH_SIZE);
        chunks.forEach(chunk -> {
            List<Trash> trashList = trashDao.findByParentIdInAndCommandAndEntityName(chunk, deletedCommand, Constants.CONTENT_TYPE.REFRESH_TOKEN.name());
            if (trashList == null || trashList.isEmpty()) {
                return;
            }
            List<RefreshToken> refreshTokens = trashList.stream().map(trash -> trashedRefreshTokenMapper.toRefreshTokenView(trash)).collect(Collectors.toList());
            refreshTokenDao.insertAllIgnoreAuditing(refreshTokens);
            trashDao.deleteAll(trashList);
        });
    }

    @Override
    public void hardDeleteByUserId(String userId) {
        List<String> commentIds =  authDao.findIdByUserId(userId);
        List<List<String>> chunks = Lists.partition(commentIds, Constants.FETCH_BATCH_SIZE);
        chunks.forEach(chunk -> {
            authDao.deleteByIdIn(chunk);
            refreshTokenDao.deleteByAuthIdIn(chunk);
        });
    }

    public void deleteAuthViewByAuthIds(List<String> authIds, String command, String reportId, String deletedBy) {
        List<List<String>> chunks = Lists.partition(authIds, Constants.FETCH_BATCH_SIZE);
        chunks.forEach(chunk -> {
            List<RefreshToken> refreshTokens = refreshTokenDao.findByAuthIdIn(chunk);
            List<Trash> trashedRefreshTokens = refreshTokens.stream().map(refreshToken -> {
                Trash trash = trashedRefreshTokenMapper.toTrash(refreshToken, command, refreshToken.getAuthId());
                trash.setReportingId(reportId);
                trash.setDeletedBy(deletedBy);
                return trash;
            }).collect(Collectors.toList());
            populateExpireAt(trashedRefreshTokens, command, trashHelper.getExpireAtInDays());
            trashDao.saveAll(trashedRefreshTokens);
            refreshTokenDao.deleteAll(refreshTokens);
        });
    }

    private void populateExpireAt(List<Trash> trashedPosts, String command, Integer expireAtInDays) {
        if (command.equals(ContentCommand.DELETE_ACCOUNT_SOFT_DELETE.name())) {
            trashedPosts.forEach(trash -> trash.setExpireAt(LocalDateTime.now().plusDays(expireAtInDays)));
        }
    }
}
