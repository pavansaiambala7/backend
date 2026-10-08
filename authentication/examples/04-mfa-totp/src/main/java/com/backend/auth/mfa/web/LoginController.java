package com.backend.auth.mfa.web;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import com.backend.auth.mfa.totp.TotpEnrollmentService;

/**
 * The login pages. The POSTs are handled by Spring Security filters: {@code /login} by form login,
 * {@code /login/totp} and {@code /login/recovery-code} by {@code SecondFactorAuthenticationFilter}.
 */
@Controller
class LoginController {

    private final TotpEnrollmentService enrollment;

    LoginController(TotpEnrollmentService enrollment) {
        this.enrollment = enrollment;
    }

    @GetMapping("/login")
    String login() {
        return "login";
    }

    /** Reachable only with a recent password step (see SecurityConfig). */
    @GetMapping("/login/totp")
    String totp(Authentication authentication) {
        return secondStep(authentication, "login-totp");
    }

    @GetMapping("/login/recovery-code")
    String recoveryCode(Authentication authentication) {
        return secondStep(authentication, "login-recovery-code");
    }

    private String secondStep(Authentication authentication, String view) {
        if (SessionFactors.hasSecondFactor(authentication)) {
            return "redirect:/";
        }
        if (!enrollment.isEnrolled(authentication.getName())) {
            // Second factor required, but none set up yet: set one up first.
            return "redirect:/mfa/totp/enroll";
        }
        return view;
    }
}
