package com.challenge.ecommerce.tps.jwt;

import com.challenge.ecommerce.tps.encript.KeyRsaSupplier;
import com.challenge.ecommerce.tps.exceptions.JwtManagementException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Getter
@AllArgsConstructor
@Component
public class JwtManagement {

	private static final ZoneId ZONEID = ZoneId.of("America/Bogota");

	private final KeyRsaSupplier keyRsaSupplier;

	private final Long expiryTimeAtMinutes;

	private JwtManagement() {

		throw new IllegalStateException("This is an utility class");
	}

	public String extractUsername(final String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public Date extractExpiration(final String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	public <T> T extractClaim(final String token, final Function<Claims, T> claimsResolver) {
		final Claims claims = getClaims(token);
		return claimsResolver.apply(claims);
	}

	public <T> T extractClaim(String token, String name, Class<T> type) {
		Claims claims = getClaims(token);
		return claims != null ? claims.get(name, type) : null;
	}

	private Boolean isTokenExpired(final String token) {
		return extractExpiration(token).before(new Date());
	}

	private Claims getClaims(final String token) {
		try {
			return Jwts.parserBuilder().setSigningKey(this.keyRsaSupplier.getPublicKey()).build().parseClaimsJws(token)
					.getBody();
		} catch (Exception e) {
			log.error("This is an error in the validity of the jwt token, the claims cannot be obtained => {}",
					e.getMessage());
			throw new JwtManagementException("Error in the Claims option for the JWT", e);
		}
	}

	public boolean validate(String token) {
		try {
			token = this.clearToken(token);
			Optional<Claims> claims = Optional.ofNullable(this.getClaims(token));
			return claims.isPresent() && !isTokenExpired(token);
		} catch (JwtManagementException e) {
			log.error("Error validating JWT token, token may be corrupted: {}", e.getMessage());
			return false;
		}
	}

	public String clearToken(final String authorization) {
		if (Objects.isNull(authorization) || authorization.isEmpty())
			return null;
		return authorization.contains("Bearer") ? authorization.split(" ")[1].trim() : authorization;

	}

	public String createToken(final String username, final List<String> roles) {
		try {
			final OffsetDateTime offsetDateTime = OffsetDateTime.now(ZONEID);
			final Date expiryTime = Date.from(offsetDateTime.plusMinutes(this.expiryTimeAtMinutes).toInstant());
			return Jwts.builder().setHeader(Map.of("typ", "JWT")).setClaims(Map.of("Role", String.join(", ", roles)))
					.setSubject(username).setExpiration(expiryTime)
					.signWith(this.keyRsaSupplier.getPrivateKey(), SignatureAlgorithm.RS256).compact();
		} catch (Exception e) {
			log.error("This is an error in the creation of the jwt token for the user {} => {} ", username,
					e.getMessage());
			throw new JwtManagementException("Error creating JWT token ", e);
		}
	}
}
