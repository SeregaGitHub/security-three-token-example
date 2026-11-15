package ru.kraser.three_token_security.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
@Slf4j
public class SignedCsrfTokenRepository implements CsrfTokenRepository {

    private final CookieCsrfTokenRepository csrfTokenRepository;
    private final CsrfTokenSigner signer;

    public SignedCsrfTokenRepository(
            CookieCsrfTokenRepository csrfTokenRepository, CsrfTokenSigner signer
    ) {
        this.csrfTokenRepository = csrfTokenRepository;
        this.signer = signer;
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        String userId = extractUserId();
        CsrfToken raw = csrfTokenRepository.generateToken(request);
        String signedValue = raw.getToken() + "." + signer.sign(raw.getToken(), userId);
        return new DefaultCsrfToken(raw.getHeaderName(), raw.getParameterName(), signedValue);
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        // token == null -> delegate удалит cookie (Max-Age=0)
        csrfTokenRepository.saveToken(token, request, response);
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        CsrfToken csrfToken = csrfTokenRepository.loadToken(request);

        if (csrfToken == null) {
            return null;   // cookie отсутствует
        }

        String value = csrfToken.getToken();
        int dotIndex = value.lastIndexOf('.');

        if (dotIndex <= 0 || dotIndex == value.length() - 1) {
            return null;   // нет подписи / пустые части -> невалидный формат
        }

        String stringToken = value.substring(0, dotIndex);
        String signature = value.substring(dotIndex + 1);
        String userId = extractUserId();

        if (!signer.isValidSignature(stringToken, signature, userId)) {
            return null;       // подпись неверна -> токен подделан
        }
        return csrfToken;      // валидный подписанный токен
    }

    private String extractUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return null;
        }

        Object principal = auth.getPrincipal();
        if (principal instanceof JwtUserDetails userDetails) return userDetails.getUserId();

        log.warn("Unsupported principal for CSRF binding: {}", principal);
        return null;
    }
}
