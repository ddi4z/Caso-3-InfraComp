package caso3;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
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
		Scanner sc = null;

		PublicKey llavePublica = ManejadorDeCifrado.generarLlavePublica(generadorLlavePublica);

		try {
			socket = new Socket("localhost", 4000);
			inputStream = new DataInputStream(socket.getInputStream());
			outputStream = new DataOutputStream(socket.getOutputStream());
			System.out.println("Conectado con el servidor: ");

			// Paso 1
			// Se envía un mensaje al servidor para iniciar la comunicación segura
			// El mensaje es de la forma "SECURE INIT,Reto"
			BigInteger Reto = new BigInteger(256, new SecureRandom());
			outputStream.writeUTF("SECURE INIT," + Reto.toString());

			// -- (Paso 2) El servidor realiza una firma digital del reto --
			// -- (Paso 3) Se recibe la firma digital del servidor --
			byte[] R1 = Base64.getDecoder().decode(inputStream.readUTF());

			// Paso 4
			// Se valida la firma digital del servidor
			boolean firmaEsValida = ManejadorDeCifrado.validarFirma(llavePublica,Reto.toByteArray(),R1);

			// Paso 5
			// Se envía un mensaje al servidor para confirmar la validez de la firma
			if (firmaEsValida) {
				outputStream.writeUTF("OK");
			} else {
				outputStream.writeUTF("ERROR");
				throw new SignatureException("La firma digital no es válida.");
			}

			// -- (Paso 6) El servidor envía los valores de p, g, gy y el vector de inicialización --

			// Paso 7
			// Se reciben los valores de p, g, gy y el vector de inicialización
			BigInteger g = new BigInteger(inputStream.readUTF());
			BigInteger p = new BigInteger(inputStream.readUTF());
			BigInteger gy = new BigInteger(inputStream.readUTF());
			IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(inputStream.readUTF()));


			// Paso 8
			// Se revisa la firma digital de los valores recibidos
			byte[] mensajeGeneradoEnBytes = (g.toString() + "," + p.toString() + "," + gy.toString()).getBytes();
			byte[] mensajeRecibidoEnBytes = Base64.getDecoder().decode(inputStream.readUTF());
			firmaEsValida = ManejadorDeCifrado.validarFirma(llavePublica, mensajeGeneradoEnBytes, mensajeRecibidoEnBytes);

			// Paso 9
			// Se envía un mensaje al servidor para confirmar la validez de la firma
			if (firmaEsValida) {
				outputStream.writeUTF("OK");
			} else {
				outputStream.writeUTF("ERROR");
				throw new SignatureException("La firma digital no es válida.");
			}

			// Paso 10
			// Se envia y genera gy al servidor
			BigInteger x = new BigInteger(256, new SecureRandom());
			BigInteger gx = g.modPow(x, p);
			outputStream.writeUTF(gx.toString());

			// Paso 11a
			// Se generan las llaves simetricas K_AB1 y K_AB2
			byte[] z = gy.modPow(x, p).toByteArray();
			SecretKey[] llaves = ManejadorDeCifrado.generarLlavesSimetricas(z);
			SecretKey K_AB1 = llaves[0];
			SecretKey K_AB2 = llaves[1];


			// -- (Paso 12) El servidor genera las llaves simetricas K_AB1 y K_AB2 y envia confirmación --
			String mensajeContinuacion = inputStream.readUTF();
			if (!mensajeContinuacion.equals("CONTINUAR")) {
				throw new IOException("Error en la comunicación en la generación de llaves simétricas");
			}

			sc = new Scanner(System.in);

			// Paso 13
			System.out.println("Introduce tu login: ");
			byte[] login = sc.nextLine().getBytes();
			byte[] loginCifrado = ManejadorDeCifrado.cifrar(K_AB1, login, iv);
			outputStream.writeUTF(Base64.getEncoder().encodeToString(loginCifrado));

			// Paso 14
			System.out.println("Introduce tu password: ");
			byte[] password = sc.nextLine().getBytes();
			byte[] passwordCifrado = ManejadorDeCifrado.cifrar(K_AB1, password, iv);
			outputStream.writeUTF(Base64.getEncoder().encodeToString(passwordCifrado));

			// -- (Paso 15) El servidor verifica el login y el password --

			// Paso 16
			// Se recibe la confirmación del servidor
			String mensajeErrorOk = inputStream.readUTF();
			if (!mensajeErrorOk.equals("OK")) {
				throw new IOException("Error en la comunicación en el login y password");
			}

			// Paso 17
			// Se envía la consulta cifrada
			System.out.println("Introduce tu consulta: ");
			byte[] consulta = new BigInteger(sc.nextLine()).toByteArray();
			byte[] consultaCifrada = ManejadorDeCifrado.cifrar(K_AB1, consulta, iv);
			outputStream.writeUTF(Base64.getEncoder().encodeToString(consultaCifrada));

			// Paso 18
			// Se envía el HMAC de la consulta
			byte[] hmac = ManejadorDeCifrado.generarHMAC(K_AB2, consulta);
			outputStream.writeUTF(Base64.getEncoder().encodeToString(hmac));

			// -- (Paso Intermerdio) El servidor recibe la consulta y el HMAC y verifica el HMAC --
			mensajeErrorOk = inputStream.readUTF();
			if (!mensajeErrorOk.equals("OK")) {
				throw new IOException("Error en la comunicación en la consulta y el HMAC");
			}

			// -- (Paso 19 Y 20) El servidor envía el resultado de la consulta cifrado y el HMAC --
			byte[] resultadoConsulta = new BigInteger(ManejadorDeCifrado.descifrar(K_AB1, Base64.getDecoder().decode(inputStream.readUTF()), iv)).toByteArray();
			byte[] hmacConsulta = Base64.getDecoder().decode(inputStream.readUTF());

			// Paso 21
			// Se verifica el HMAC del resultado de la consulta
			byte[] hmacCalculado = ManejadorDeCifrado.generarHMAC(K_AB2, resultadoConsulta);

			if (!MessageDigest.isEqual(hmacConsulta, hmacCalculado)) {
				throw new IOException("Error en la comunicación en el resultado de la consulta y el HMAC");
			}
			System.out.println("El numero obtenido es: " + new BigInteger(resultadoConsulta));

		}
		catch (IOException e) {
			System.out.println("Conexion con el servidor cerrada");
		}
		finally {
			try {
				if (inputStream != null) inputStream.close();
				if (outputStream != null) outputStream.close();
				if (socket != null) socket.close();
				if (sc != null) sc.close();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}
	}



}
