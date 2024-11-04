package com.challenge.ecommerce.tps.exceptions;

public class KeyStoreRsaException extends SecurityLibraryException {

	public KeyStoreRsaException(String message) {
		super(String.format("Error obtaining keys from JKS: %s", message));
	}

	public KeyStoreRsaException(String message, Throwable cause) {
		super(String.format("Error obtaining keys from JKS: %s", message), cause);
	}

}
