package org.example.bookservice;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class BookResource {

    @GetMapping("/books")
    public ResponseEntity<String> getBooks(Authentication authentication) { // authentication parameter is not necessary
        // The lines below are purely to demonstrate the existence of the jwt, you do not need them for your endpoints
        assert authentication instanceof JwtAuthenticationToken;
        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
        String username = authentication.getName();
        String jwtString = jwtAuthenticationToken.getToken().getTokenValue();

        return ResponseEntity.ok("Hi " + username + ", here are some books [book1, book2],  " + " also here is your jwt : " + jwtString);
    }
}
