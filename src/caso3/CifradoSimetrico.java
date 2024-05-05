package caso3;


import java.math.BigInteger;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CifradoSimetrico {
	private static final String PADDING = "AES/CBC/PKCS5Padding";
	private static IvParameterSpec iv = generateIv();

	public static IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}


	public static byte[] cifrar(SecretKey llave, String texto) {
		byte[] textoCifrado;

		try {
			Cipher cifrador = Cipher.getInstance(PADDING);
			byte[] textoClaro = texto.getBytes();

			cifrador.init(Cipher.ENCRYPT_MODE, llave, iv);
			textoCifrado = cifrador.doFinal(textoClaro);

			return textoCifrado;
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
			return null;
		}
	}

	public static byte[] descifrar(SecretKey llave, byte[] texto) {
		byte[] textoClaro;

		try {
			Cipher cifrador = Cipher.getInstance(PADDING);

			cifrador.init(Cipher.DECRYPT_MODE, llave, iv);
			textoClaro = cifrador.doFinal(texto);
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
			return null;
		}
		return textoClaro;
	}
}
