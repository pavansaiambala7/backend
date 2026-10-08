package com.backend.auth.session.web;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
class PageController {

    /** Rendered by us; Spring Security only processes the POST to /login. */
    @GetMapping("/login")
    String login() {
        return "login";
    }

    /** The protected page. Reaching it at all requires an authenticated session. */
    @GetMapping("/")
    String home(Authentication authentication, Model model) {
        model.addAttribute("username", authentication.getName());
        return "home";
    }
}
