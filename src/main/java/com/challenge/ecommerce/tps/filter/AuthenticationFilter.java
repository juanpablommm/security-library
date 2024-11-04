package com.challenge.ecommerce.tps.filter;

import com.challenge.ecommerce.tps.jwt.JwtManagement;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

@Builder
@AllArgsConstructor
@Getter
@Setter
@Slf4j
public final class AuthenticationFilter extends OncePerRequestFilter {

	private final JwtManagement jwtManagement;
	private final List<String> excludeUrlPatterns;
	private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

	@Override
	public void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain) throws ServletException, IOException {

		this.addIpAddress(request);

		final Optional<String> authorization = Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION));
		if (authorization.isEmpty() || !jwtManagement.validate(authorization.get())) {
			this.handleInvalidAuthentication(response, authorization.isEmpty());
			return;
		}

		final String email = jwtManagement.extractUsername(authorization.get());
		final String role = jwtManagement.extractClaim(authorization.get(), claims -> claims.get("Role", String.class));
		this.setAuthentication(email, role);

		filterChain.doFilter(request, response);
	}

	private void handleInvalidAuthentication(HttpServletResponse response, boolean isEmptyAuth) throws IOException {
		if (isEmptyAuth)
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authorization header missing");

		response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid Authentication");

	}

	private void setAuthentication(final String email, final String role) {
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(email, null,
				List.of(new SimpleGrantedAuthority(role)));
		SecurityContextHolder.getContext().setAuthentication(authToken);
	}

	@Override
	protected boolean shouldNotFilter(final @NonNull HttpServletRequest request) {
		this.addIpAddress(request);
		return excludeUrlPatterns.stream().anyMatch(pattern -> PATH_MATCHER.match(pattern, request.getRequestURI()));
	}

	private void addIpAddress(final HttpServletRequest request) {
		String ipAddress = Optional.ofNullable(request.getHeader("X-Forwarded-For"))
				.map(header -> header.split(",")[0].trim()).orElse(request.getRemoteAddr());
		request.setAttribute("ipAddress", ipAddress);
	}
}
