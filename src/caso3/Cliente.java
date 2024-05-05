package caso3;


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Cliente {
	private BigInteger p;
	private BigInteger g;
	private BigInteger x;
	private BigInteger gx;
	private BigInteger gy;

	private String login;
	private String password;
	private BigInteger consulta;

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


			




			Scanner sc = new Scanner(System.in);
			System.out.println("Introduce tu consulta: ");
			String strFichero = sc.nextLine();

			outputStream.writeUTF(strFichero);

			BigInteger resultadoConsulta = new BigInteger(inputStream.readUTF());

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
