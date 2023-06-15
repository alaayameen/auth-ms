package com.social.auth.trash.rest;

import com.social.auth.trash.controllers.ContentManagementController;
import com.social.swagger.api.contentmanagement.ContentManagementApi;
import com.social.swagger.model.contentmanagement.ContentManagementRequest;
import io.swagger.annotations.ApiParam;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@AllArgsConstructor
public class ContentManagementRest implements ContentManagementApi {

    private final ContentManagementController contentManagementController;

    @Override
    public ResponseEntity<Void> manageContentByContentId(@ApiParam(value = "" ,required=true) @RequestHeader(value="Authorization", required=true) String authorization,
                                                          @ApiParam(value = ""  )  @Valid @RequestBody ContentManagementRequest contentManagementRequest) {
        contentManagementController.manageContentByContentId(authorization, contentManagementRequest);
        return ResponseEntity.noContent().build();
    }
}
