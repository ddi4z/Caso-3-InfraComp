package caso3;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Cliente {
	private static final String generadorLlavePublica = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgefqw/yu0jgJTobhAouBAd8CbOFYDHgANfw9ymeY2YO++DsiqMFLqPp9hyhf9sE/Lz/oBb+EsP+EPdh96kdh8P9Vt9HJ4PBqdIx3Z6psSWKXn06Dj4NIKnTCvJ1H/AbOjRuoyP9O6LfIVpquJpiKnCCuroGSI6LuagiA2f4wB5L2bGmJYahqyGgUys7pFBFvYW+NjvD4Lgs72+kSIZ0kwr6nRRr0tVGeqlmlxivbSnr6ZN5CDLjMSDGwFX6LEPiFSCDim+M8qLxRItzmW3TKVsNnkIgksJOVKnMa5BOnoP/wbaRvnOfuJYn42ADnrro1bdDZcleVP2VAMIHhpvsWjwIDAQAB";


	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
		DataInputStream inputStream = null;
		DataOutputStream outputStream = null;
		Socket socket = null;

		
		

		PublicKey publica = generarLlavePublica(generadorLlavePublica);

		try {
			socket = new Socket("localhost", 4000);
			System.out.println("Conectado con el servidor: ");

			inputStream = new DataInputStream(socket.getInputStream());
			outputStream = new DataOutputStream(socket.getOutputStream());


			// Paso 1
			BigInteger Reto = new BigInteger(256, new SecureRandom());
			outputStream.writeUTF("SECURE INIT," + Reto.toString());

			// Paso 3

			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(publica);
			signature.update(Reto.toByteArray());

			byte[] R1 = Base64.getDecoder().decode(inputStream.readUTF());

			boolean verified = signature.verify(R1);

			if (verified) {
				outputStream.writeUTF("OK");
			} else {
				outputStream.writeUTF("ERROR");
				throw new SignatureException("La firma digital no es válida.");
			}

			BigInteger g = new BigInteger(inputStream.readUTF());
			BigInteger p = new BigInteger(inputStream.readUTF());
			BigInteger gy = new BigInteger(inputStream.readUTF());
			IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(inputStream.readUTF()));
			String mensajePGY = g.toString() + "," + p.toString() + "," + gy.toString();

			signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(publica);
			signature.update(mensajePGY.getBytes());

			byte[] PGYBytes = Base64.getDecoder().decode(inputStream.readUTF());

			boolean verifiedPGY = signature.verify(PGYBytes);

			if (verifiedPGY) {
				outputStream.writeUTF("OK");
			} else {
				outputStream.writeUTF("ERROR");
				throw new SignatureException("La firma digital no es válida.");
			}

			BigInteger x = new BigInteger(256, new SecureRandom());
			BigInteger gx = g.modPow(x, p);
			outputStream.writeUTF(gx.toString());

			BigInteger z = gy.modPow(x, p);

			byte[] bytes = z.toByteArray();
			MessageDigest digest = MessageDigest.getInstance("SHA-512");
			byte[] hash = digest.digest(bytes);
			int halfLength = hash.length / 2;
			byte[] hashHalf1 = new byte[halfLength];
			byte[] hashHalf2 = new byte[halfLength];
			System.arraycopy(hash, 0, hashHalf1, 0, halfLength);
			System.arraycopy(hash, halfLength, hashHalf2, 0, halfLength);

			SecretKey key1 = CifradoSimetrico.generarLlave(hashHalf1);
			SecretKey key2 = CifradoSimetrico.generarLlave(hashHalf2);

			String mensaje = inputStream.readUTF();
			if (!mensaje.equals("CONTINUAR")) {
				throw new IOException("Error en la comunicación");
			}

			Scanner sc = new Scanner(System.in);

			System.out.println("Introduce tu login: ");
			String login = sc.nextLine();
			System.out.println("Introduce tu password: ");
			String password = sc.nextLine();

			byte[] loginCifrado = CifradoSimetrico.cifrar(key1, login.getBytes(), iv);
			byte[] passwordCifrado = CifradoSimetrico.cifrar(key1, password.getBytes(), iv);


			outputStream.writeUTF(Base64.getEncoder().encodeToString(loginCifrado));
			outputStream.writeUTF(Base64.getEncoder().encodeToString(passwordCifrado));

			String mensajeErrorOk = inputStream.readUTF();
			if (!mensajeErrorOk.equals("OK")) {
				System.out.println("Conexion con el servidor cerrada al verificar usuario");
				sc.close();
				return;
			}


			System.out.println("Introduce tu consulta: ");
			BigInteger consulta = new BigInteger(sc.nextLine());
			byte[] consultaCifrada = CifradoSimetrico.cifrar(key1, consulta.toByteArray(), iv);
			byte[] hmac = CifradoSimetrico.generarHMAC(key2, consulta.toByteArray());


			outputStream.writeUTF(Base64.getEncoder().encodeToString(consultaCifrada));
			outputStream.writeUTF(Base64.getEncoder().encodeToString(hmac));

			mensajeErrorOk = inputStream.readUTF();

			if (!mensajeErrorOk.equals("OK")) {
				System.out.println("Conexion con el servidor cerrada al verificar consulta");
				sc.close();
				return;
			}

			BigInteger resultadoConsulta = new BigInteger(CifradoSimetrico.descifrar(key1, Base64.getDecoder().decode(inputStream.readUTF()), iv));
			byte[] hmacConsulta = Base64.getDecoder().decode(inputStream.readUTF());
			byte[] hmacCalculado = CifradoSimetrico.generarHMAC(key2, resultadoConsulta.toByteArray());



			if (!MessageDigest.isEqual(hmacConsulta, hmacCalculado)) {
				System.out.println("Conexion con el servidor cerrada por error en el HMAC");
				sc.close();
				return;
			}

			System.out.println("El numero obtenido es: " + resultadoConsulta.toString());
			sc.close();

		} catch (IOException e) {
			System.out.println("Conexion con el servidor cerrada");
		}finally {
			try {
				if (inputStream != null) {
					inputStream.close();
				}
				if (outputStream != null) {
					outputStream.close();
				}
				if (socket != null) {
					socket.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public static PublicKey generarLlavePublica(String llaveCodificada) throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] publicKeyBytes = Base64.getDecoder().decode(llaveCodificada);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		return publicKey;
	}

}
