package com.example.authservice.repository;

import com.example.authservice.entity.RefreshToken;
import com.example.authservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByUser(User user);

    Optional<RefreshToken> findByTokenId(String tokenId);

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.user.id = :userId")
    void deleteByUserId(@Param("userId") UUID userId);

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.tokenHash = :tokenHash")
    void deleteByTokenHashValue(@Param("tokenHash") String tokenHash);

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.tokenId = :tokenId")
    void deleteByTokenId(@Param("tokenId") String tokenId);
}