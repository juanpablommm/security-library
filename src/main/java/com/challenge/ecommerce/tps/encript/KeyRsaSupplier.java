package com.challenge.ecommerce.tps.encript;

import com.challenge.ecommerce.tps.exceptions.KeyStoreRsaException;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.util.Base64;
import javax.crypto.Cipher;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Getter
@Component
public final class KeyRsaSupplier {

	private final String passwordJks;
	private final String aliasJks;
	private final String path;
	private final KeyStore keyStore;
	private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

	public KeyRsaSupplier(final String passwordJks, final String aliasJks, final String path)
			throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
		this.passwordJks = passwordJks;
		this.aliasJks = aliasJks;
		this.path = path;
		this.keyStore = loadKeyStore();
	}

	private KeyStore loadKeyStore()
			throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
		try (FileInputStream fis = new FileInputStream(this.path)) {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(fis, this.passwordJks.toCharArray());
			return ks;
		}
	}

	public PublicKey getPublicKey() {
		try {
			return this.keyStore.getCertificate(this.aliasJks).getPublicKey();
		} catch (KeyStoreException e) {
			throw new KeyStoreRsaException("Error obtaining public key from keystore", e);
		}
	}

	public Key getPrivateKey() {
		try {
			return keyStore.getKey(this.aliasJks, this.passwordJks.toCharArray());
		} catch (Exception e) {
			throw new KeyStoreRsaException("Error obtaining public key from keystore", e);
		}
	}

	public String encrypt(String text) {
		try {
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, this.getPublicKey());
			byte[] encryptedData = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
			text = Base64.getEncoder().encodeToString(encryptedData);
		} catch (Exception e) {
			log.error("{} : {} => {}", e.getMessage(), text, e.getMessage());
		}
		return text;
	}

	public String decrypt(String text) {
		try {
			Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
			text = text.replace(" ", "+");
			cipher.init(Cipher.DECRYPT_MODE, this.getPrivateKey());
			byte[] decodedData = Base64.getDecoder().decode(text);
			byte[] decryptedData = cipher.doFinal(decodedData);
			text = new String(decryptedData, StandardCharsets.UTF_8);
		} catch (Exception e) {
			log.error("{} : {} => {}", e.getMessage(), text, e.getMessage());
		}
		return text;
	}
}
