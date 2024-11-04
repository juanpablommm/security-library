package com.challenge.ecommerce.tps.exceptions;

public class SecurityLibraryException extends RuntimeException {

	public SecurityLibraryException(String message) {
		super(String.format("Error in security library: %s", message));
	}

	public SecurityLibraryException(String message, Throwable cause) {
		super(String.format("Error in security library: %s", message), cause);
	}
}
