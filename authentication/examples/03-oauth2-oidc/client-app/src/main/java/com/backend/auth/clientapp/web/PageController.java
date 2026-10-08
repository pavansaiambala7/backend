package com.backend.auth.clientapp.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
class PageController {

    @GetMapping("/")
    String home(@AuthenticationPrincipal OidcUser user, Model model) {
        model.addAttribute("name", user.getFullName() != null ? user.getFullName() : user.getSubject());
        model.addAttribute("subject", user.getSubject());
        model.addAttribute("issuer", user.getIssuer());
        return "index";
    }

    /** Where the authorization server sends the browser after RP-initiated logout. Public. */
    @GetMapping("/logged-out")
    String loggedOut() {
        return "logged-out";
    }
}
