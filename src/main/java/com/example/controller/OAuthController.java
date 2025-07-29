package com.example.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/oauth")
public class OAuthController {
    
    @GetMapping("/login")
    public String login() {
        return "oauth/login";
    }
    
    @GetMapping("/home")
    public String home(Authentication authentication, Model model) {
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        model.addAttribute("username", oauth2User.getAttribute("login"));
        model.addAttribute("name", oauth2User.getAttribute("name"));
        return "oauth/home";
    }
    
    @GetMapping("/about")
    public String about() {
        return "oauth/about";
    }
}
