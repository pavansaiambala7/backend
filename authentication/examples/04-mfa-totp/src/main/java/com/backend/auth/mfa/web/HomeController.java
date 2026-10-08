package com.backend.auth.mfa.web;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import com.backend.auth.mfa.recovery.RecoveryCodeService;
import com.backend.auth.mfa.security.SecondFactor;

/** Protected pages: reachable only with password AND (TOTP OR recovery code). */
@Controller
class HomeController {

    private final RecoveryCodeService recoveryCodes;

    HomeController(RecoveryCodeService recoveryCodes) {
        this.recoveryCodes = recoveryCodes;
    }

    @GetMapping("/")
    String home(Authentication authentication, Model model) {
        String username = authentication.getName();
        model.addAttribute("username", username);
        model.addAttribute("factors", SessionFactors.of(authentication));
        model.addAttribute("recoveryCodesLeft", recoveryCodes.remaining(username));
        model.addAttribute("usedRecoveryCode", SessionFactors.has(authentication, SecondFactor.RECOVERY_CODE));
        return "home";
    }

    /** A new set replaces every old code, used or not. */
    @PostMapping("/mfa/recovery-codes")
    String regenerateRecoveryCodes(Authentication authentication, Model model) {
        model.addAttribute("recoveryCodes", recoveryCodes.issueNewSet(authentication.getName()));
        model.addAttribute("continueUrl", "/");
        return "recovery-codes";
    }
}
