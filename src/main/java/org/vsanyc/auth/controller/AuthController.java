package org.vsanyc.auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;

@RestController
public class AuthController {

    @GetMapping("/simple")
    public String simpleResponse() {
        return "Simple auth server response: " + LocalDateTime.now();
    }
}
