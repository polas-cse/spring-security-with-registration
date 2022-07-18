package com.security.client.repository;

import com.security.client.entity.PasswordResertToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResertToken, Long> {
    PasswordResertToken findByToken(String token);
}
