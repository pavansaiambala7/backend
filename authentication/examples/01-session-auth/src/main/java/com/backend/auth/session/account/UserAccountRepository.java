package com.backend.auth.session.account;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserAccountRepository extends JpaRepository<UserAccount, Long> {

    /** @param normalizedEmail an address already passed through {@link UserAccount#normalizeEmail} */
    Optional<UserAccount> findByEmail(String normalizedEmail);

    boolean existsByEmail(String normalizedEmail);
}
