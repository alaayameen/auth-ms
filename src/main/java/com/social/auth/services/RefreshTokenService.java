package com.social.auth.services;

import com.social.auth.data.mongo.dao.RefreshTokenRepository;
import com.social.auth.data.mongo.models.RefreshToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
  @Value("${auth.jwt.jwtRefreshExpirationMs}")
  private Long refreshTokenDurationMs;

  @Autowired
  private RefreshTokenRepository refreshTokenRepository;


  public Optional<RefreshToken> findByToken(String token) {
    return refreshTokenRepository.findByToken(token);
  }

  public RefreshToken createRefreshToken(String authId) {
    RefreshToken refreshToken = new RefreshToken();

    refreshToken.setAuthId(authId);
    refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
    refreshToken.setToken(UUID.randomUUID().toString());

    refreshToken = refreshTokenRepository.insert(refreshToken);
    return refreshToken;
  }

  public RefreshToken verifyExpiration(RefreshToken token) {
    if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
    	
    //Temporary for users retention.
    	token.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
    	token = refreshTokenRepository.save(token);
      //refreshTokenRepository.delete(token);
      //throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
    }
    return token;
  }
}