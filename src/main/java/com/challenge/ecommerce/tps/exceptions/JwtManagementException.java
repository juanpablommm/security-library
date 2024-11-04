package com.challenge.ecommerce.tps.exceptions;

public class JwtManagementException extends SecurityLibraryException {

	public JwtManagementException(String message) {
		super(String.format("Error in JWT token manipulation:  %s", message));

	}

	public JwtManagementException(String message, Throwable cause) {
		super(String.format("Error in JWT token manipulation:  %s", message), cause);
	}
}
