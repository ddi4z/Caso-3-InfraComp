package caso3;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class ManejadorDeCifrado {
	
	private static final String ALG_GENERADOR_SIMETRICO = "AES/CBC/PKCS5Padding";
	private static final String ALG_GENERADOR_FIRMA = "SHA256withRSA";
	private static final String ALG_GENERADOR_HASH = "SHA-512";
	private static final String ALG_GENERADOR_HMAC = "HmacSHA256";
	private static final String ALGORITMO_SIMETRICO = "AES";
	private static final String ALGORITMO_ASIMETRICO = "RSA";

	/*
	 * Metodo que cifra de forma simétrica un texto convertido a bytes
	 * @param llave: Llave simetrica K_AB1 para cifrar
	 * @param textoClaro: Texto a cifrar convertido a bytes
	 * @param iv: Vector de inicializacion del CBC
	*/
	public static byte[] cifrar(SecretKey llave, byte[] textoClaro, IvParameterSpec iv) {
		byte[] textoCifrado = null;
		try {
			Cipher cifrador = Cipher.getInstance(ALG_GENERADOR_SIMETRICO);
			cifrador.init(Cipher.ENCRYPT_MODE, llave, iv);
			textoCifrado = cifrador.doFinal(textoClaro);
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
		}
		return textoCifrado;
	}

	/*
	 * Metodo que descifra de forma simétrica un texto cifrado convertido a bytes
	 * @param llave: Llave simetrica K_AB1 para descifrar
	 * @param texto: Texto cifrado convertido a bytes
	 * @param iv: Vector de inicializacion del CBC
	 * @return textoClaro: Arreglo de bytes que contiene el texto descifrado
	*/
	public static byte[] descifrar(SecretKey llave, byte[] texto, IvParameterSpec iv) {
		byte[] textoClaro = null;
		try {
			Cipher cifrador = Cipher.getInstance(ALG_GENERADOR_SIMETRICO);
			cifrador.init(Cipher.DECRYPT_MODE, llave, iv);
			textoClaro = cifrador.doFinal(texto);
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
		}
		return textoClaro;
	}

	/*
	 * Metodo que genera un HMAC de un texto convertido a bytes
	 * @param key: Llave simetrica K_AB2 para generar el HMAC
	 * @param texto: Texto a cifrar convertido a bytes
	 * @return hmacBytes: Arreglo de bytes que contiene el HMAC
	*/
	public static byte[] generarHMAC(SecretKey key, byte[] texto) {
		byte[] hmacBytes = null;
		try {
			Mac mac = Mac.getInstance(ALG_GENERADOR_HMAC);
			mac.init(key);
			hmacBytes = mac.doFinal(texto);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return hmacBytes;
	}

	/*
	 * Metodo que genera una llave simetrica a partir de un arreglo de bytes
	 * @param bytesMitadLlave: Arreglo de bytes que contiene la mitad de la llave generada con Diffie-Hellman
	 * @return nuevaLlave: Llave simetrica generada
	*/
	private static SecretKey generarLlave(byte[] bytesMitadLlave) {
		SecretKey nuevaLlave = new SecretKeySpec(bytesMitadLlave, 0, bytesMitadLlave.length, ALGORITMO_SIMETRICO);
		return nuevaLlave;
	}

	/*
	 * Metodo que genera una firma digital
	 * @param llavePrivada: Llave privada del emisor
	 * @param mensaje: Mensaje a firmar
	 * @return firma: Arreglo de bytes que contiene la firma digital
	*/
	public static byte[] generarFirma(PrivateKey llavePrivada, byte[] mensaje) {
		byte[] firma = null;
		try {
			Signature signature = Signature.getInstance(ALG_GENERADOR_FIRMA);
			signature.initSign(llavePrivada);
			signature.update(mensaje);
			firma = signature.sign();
		}
		catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
		}
		return firma;
	}

	/*
	 * Metodo que valida una firma digital
	 * @param llavePublica: Llave publica del emisor
	 * @param actual: Mensaje original
	 * @param recibido: Firma digital recibida
	 * @return esValida: Booleano que indica si la firma es valida
	*/
	public static boolean validarFirma(PublicKey llavePublica, byte[] actual, byte[] recibido) {
		boolean esValida = false;
		try {
			Signature firma = Signature.getInstance(ALG_GENERADOR_FIRMA);
			firma.initVerify(llavePublica);
			firma.update(actual);
			esValida = firma.verify(recibido);
		}
		catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
		}
		return esValida;
	}

	/*
	 * Metodo que genera dos llaves simetricas a partir de un arreglo de bytes
	 * @param z: Arreglo de bytes que contiene la llave generada con Diffie-Hellman
	 * @return llaves: Arreglo de llaves simetricas generadas
	*/
	public static SecretKey[] generarLlavesSimetricas(byte[] z){
		SecretKey K_AB1 = null;
		SecretKey K_AB2 = null;
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(ALG_GENERADOR_HASH);
			byte[] hash = digest.digest(z);
			int longitudMitad = hash.length / 2;
			byte[] primeraMitad = new byte[longitudMitad];
			byte[] segundaMitad = new byte[longitudMitad];
			System.arraycopy(hash, 0, primeraMitad, 0, longitudMitad);
			System.arraycopy(hash, longitudMitad, segundaMitad, 0, longitudMitad);
			K_AB1 = ManejadorDeCifrado.generarLlave(primeraMitad);
			K_AB2 = ManejadorDeCifrado.generarLlave(segundaMitad);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		SecretKey[] llaves = {K_AB1, K_AB2};
		return llaves;
	}

	/*
	 * Metodo que genera una llave privada a partir de una llave codificada en base64 (String)
	 * @param llaveCodificada: String que contiene la llave privada codificada en base64
	 * @return llavePrivada: Llave privada generada
	*/
	public static PrivateKey generarLlavePrivada(String llaveCodificada) {
		PrivateKey llavePrivada = null;
		try {
			byte[] llavePrivadaEnBytes = Base64.getDecoder().decode(llaveCodificada);
			KeyFactory keyFactory = KeyFactory.getInstance(ALGORITMO_ASIMETRICO);
			llavePrivada = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(llavePrivadaEnBytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return llavePrivada;
	}

	/*
	 * Metodo que genera una llave publica a partir de una llave codificada en base64 (String)
	 * @param llaveCodificada: String que contiene la llave publica codificada en base64
	 * @return llavePublica: Llave publica generada
	*/
	public static PublicKey generarLlavePublica(String llaveCodificada) throws InvalidKeySpecException, NoSuchAlgorithmException {
		PublicKey llavePublica = null;
		try {
			byte[] llavePublicaEnBytes = Base64.getDecoder().decode(llaveCodificada);
			KeyFactory keyFactory = KeyFactory.getInstance(ALGORITMO_ASIMETRICO);
			llavePublica = keyFactory.generatePublic(new X509EncodedKeySpec(llavePublicaEnBytes));
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return llavePublica;
	}

}
