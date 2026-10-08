package com.backend.auth.apikeys.admin;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.backend.auth.apikeys.admin.AdminAccountsProperties.AdminAccount;

@Service
public class AdminUserDetailsService implements UserDetailsService {

    private final Map<String, AdminAccount> accounts;

    AdminUserDetailsService(AdminAccountsProperties properties) {
        this.accounts = properties.accounts().stream()
                .collect(Collectors.toUnmodifiableMap(AdminAccount::username, Function.identity()));
    }

    /** A fresh object per call: Spring Security erases the password from the principal after authentication. */
    @Override
    public AdminUser loadUserByUsername(String username) {
        AdminAccount account = accounts.get(username);
        if (account == null) {
            throw new UsernameNotFoundException("Unknown administrator");
        }
        return new AdminUser(account.username(), account.passwordHash(), account.owner());
    }
}
