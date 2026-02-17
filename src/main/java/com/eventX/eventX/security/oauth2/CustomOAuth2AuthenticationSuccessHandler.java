package com.eventX.eventX.security.oauth2;

import com.eventX.eventX.model.User;
import com.eventX.eventX.repository.UserRepository;
import com.eventX.eventX.security.jwt.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CustomOAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Value("${app.frontend.url:http://localhost:3000}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
            OAuth2User oauth2User = oauthToken.getPrincipal();
            String registrationId = oauthToken.getAuthorizedClientRegistrationId(); // "google" or "github"

            String email = oauth2User.getAttribute("email");
            String name = oauth2User.getAttribute("name"); // For Google
            if (name == null && "github".equals(registrationId)) {
                name = oauth2User.getAttribute("login"); // For GitHub
            }
            String providerId = oauth2User.getName(); // Unique ID from OAuth2 provider

            Optional<User> existingUser = userRepository.findByProviderAndProviderId(registrationId, providerId);
            User user;

            if (existingUser.isPresent()) {
                user = existingUser.get();
                // Update user details if necessary
                user.setEmail(email);
                user.setUsername(name);
                userRepository.save(user);
            } else {
                user = new User();
                user.setUsername(name);
                user.setEmail(email);
                user.setProvider(registrationId);
                user.setProviderId(providerId);
                user.setRoles(Collections.singletonList("ROLE_USER"));
                userRepository.save(user);
            }

            String jwtToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            // Redirect to a frontend URL with the JWT token
            String targetUrl = UriComponentsBuilder.fromUriString(frontendUrl + "/oauth2/redirect")
                    .queryParam("access_token", "Bearer " + jwtToken)
                    .queryParam("refresh_token", refreshToken)
                    .build().toUriString();

            getRedirectStrategy().sendRedirect(request, response, targetUrl);
        } else {
            super.onAuthenticationSuccess(request, response, authentication);
        }
    }
}
