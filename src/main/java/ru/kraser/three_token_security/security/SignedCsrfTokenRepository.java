package ru.kraser.three_token_security.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;

public class SignedCsrfTokenRepository implements CsrfTokenRepository {

    private final CookieCsrfTokenRepository delegate;
    private final CsrfTokenSigner signer;

    public SignedCsrfTokenRepository(
            CookieCsrfTokenRepository delegate, CsrfTokenSigner signer
    ) {
        this.delegate = delegate;
        this.signer = signer;
    }

    @Override
    public CsrfToken generateToken(HttpServletRequest request) {
        CsrfToken raw = delegate.generateToken(request);
        String signedValue = raw.getToken() + "." + signer.sign(raw.getToken());
        return new DefaultCsrfToken(raw.getHeaderName(), raw.getParameterName(), signedValue);
    }

    @Override
    public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        // token == null -> delegate удалит cookie (Max-Age=0)
        delegate.saveToken(token, request, response);
    }

    @Override
    public CsrfToken loadToken(HttpServletRequest request) {
        CsrfToken token = delegate.loadToken(request);
        if (token == null) {
            return null;   // cookie отсутствует
        }
        String value = token.getToken();
        int dotIndex = value.lastIndexOf('.');
        if (dotIndex <= 0 || dotIndex == value.length() - 1) {
            return null;   // нет подписи / пустые части -> невалидный формат
        }
        String rawToken = value.substring(0, dotIndex);
        String signature = value.substring(dotIndex + 1);
        if (!signer.isValidSignature(rawToken, signature)) {
            return null;   // подпись неверна -> токен подделан
        }
        return token;      // валидный подписанный токен
    }
}
