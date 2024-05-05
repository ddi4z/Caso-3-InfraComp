package caso3;


import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class CifradoSimetrico {
	private static final String PADDING = "AES/CBC/PKCS5Padding";


	public static byte[] cifrar(SecretKey llave, byte[] textoClaro, IvParameterSpec iv) {
		byte[] textoCifrado;

		try {
			Cipher cifrador = Cipher.getInstance(PADDING);

			cifrador.init(Cipher.ENCRYPT_MODE, llave, iv);
			textoCifrado = cifrador.doFinal(textoClaro);

			return textoCifrado;
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
			return null;
		}
	}

	public static byte[] descifrar(SecretKey llave, byte[] texto, IvParameterSpec iv) {
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

	public static byte[] generarHMAC (SecretKey key, byte[] texto) throws InvalidKeyException, NoSuchAlgorithmException {
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(key);
		byte[] hmacBytes = mac.doFinal(texto);
		return hmacBytes;
	}

	public static SecretKey generarLlave(byte[] hashHalf1) {
		SecretKey key1 = new SecretKeySpec(hashHalf1, 0, hashHalf1.length, "AES");
		return key1;
	}
}
