package com.backend.auth.mfa.web;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.backend.auth.mfa.security.SecondFactor;
import com.backend.auth.mfa.security.SecondFactorFailureHandler;
import com.backend.auth.mfa.security.SecondFactorThrottledException;
import com.backend.auth.mfa.totp.PendingEnrollment;
import com.backend.auth.mfa.totp.TotpEnrollmentService;

import jakarta.servlet.http.HttpServletResponse;

/**
 * First-time TOTP setup. SecurityConfig lets a session in here only if its password step is recent and the account
 * has no active authenticator yet.
 */
@Controller
class EnrollmentController {

    private final TotpEnrollmentService enrollment;

    EnrollmentController(TotpEnrollmentService enrollment) {
        this.enrollment = enrollment;
    }

    @GetMapping("/mfa/totp/enroll")
    String intro() {
        return "enroll-start";
    }

    /** POST, not GET: it creates a new secret, and a GET must be safe to repeat or prefetch. */
    @PostMapping("/mfa/totp/enroll")
    String start(Authentication authentication, Model model) {
        model.addAttribute("enrollment", enrollment.start(authentication.getName()));
        return "enroll-confirm";
    }

    @PostMapping("/mfa/totp/confirm")
    String confirm(@RequestParam(defaultValue = "") String code, Authentication authentication, Model model,
                   HttpServletResponse response) {
        String username = authentication.getName();
        Optional<PendingEnrollment> pending = enrollment.pending(username);
        if (pending.isEmpty()) {
            return "redirect:/mfa/totp/enroll";
        }
        Optional<List<String>> recoveryCodes = enrollment.confirm(username, code);
        if (recoveryCodes.isEmpty()) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            model.addAttribute("enrollment", pending.get());
            model.addAttribute("error", true);
            return "enroll-confirm";
        }
        model.addAttribute("recoveryCodes", recoveryCodes.get());
        // The session still holds only the password factor: the user now signs in with their next code.
        model.addAttribute("continueUrl", SecondFactor.TOTP.loginPage());
        return "recovery-codes";
    }

    @ExceptionHandler(SecondFactorThrottledException.class)
    void tooManyAttempts(SecondFactorThrottledException exception, HttpServletResponse response) throws IOException {
        SecondFactorFailureHandler.writeTooManyRequests(response, exception);
    }
}
