package edu.icet.service;

import edu.icet.model.User;
import edu.icet.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository repository;
    private final AuthenticationManager authManager;
    private final JWTService jwtService;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public User register(User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        return repository.save(user);
    }

    public String verify(User user) {
        Authentication authentication =
                authManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));

        if (authentication.isAuthenticated())
            return jwtService.generateToken(user.getUsername());

        return "failure";
    }
}
