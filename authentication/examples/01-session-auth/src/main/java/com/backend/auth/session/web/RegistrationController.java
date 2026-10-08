package com.backend.auth.session.web;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.backend.auth.session.account.RegistrationService;
import com.backend.auth.session.password.PasswordPolicy;
import com.backend.auth.session.password.WeakPasswordException;

@Controller
@RequestMapping("/register")
class RegistrationController {

    private static final String VIEW = "register";

    private final RegistrationService registrations;

    RegistrationController(RegistrationService registrations) {
        this.registrations = registrations;
    }

    @ModelAttribute("minPasswordLength")
    int minPasswordLength() {
        return PasswordPolicy.MIN_LENGTH;
    }

    @GetMapping
    String form(Model model) {
        model.addAttribute("form", RegistrationForm.empty());
        return VIEW;
    }

    /**
     * New address or already registered: both end in the same redirect, so the form cannot be used
     * to find out who has an account. (The CSRF token is checked by Spring Security before this runs.)
     */
    @PostMapping
    String register(@Valid @ModelAttribute("form") RegistrationForm form, BindingResult errors,
                    HttpServletResponse response) {
        if (errors.hasErrors()) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return VIEW;
        }
        try {
            registrations.register(form.email(), form.password());
        } catch (WeakPasswordException e) {
            errors.rejectValue("password", "weak", e.getMessage());
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            return VIEW;
        }
        return "redirect:/login?registered";
    }
}
