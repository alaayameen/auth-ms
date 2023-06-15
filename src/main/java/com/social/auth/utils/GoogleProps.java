package com.social.auth.utils;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "google")
@Data
public class GoogleProps {
    private List<String> appIds;
}