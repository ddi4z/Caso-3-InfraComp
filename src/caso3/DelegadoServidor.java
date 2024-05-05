package caso3;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class DelegadoServidor extends Thread {
	private int id;
	private Socket cliente = null;
	private DataOutputStream outputStream = null;
	private DataInputStream inputStream = null;
	private PrivateKey privada;
	private static BigInteger p;
    private static BigInteger g;

	private static long tiempoGenerarFirma = 0;
	private static long tiempoDescifrarConsulta = 0;
	private static long tiempoVerificarCodigo = 0;

	public DelegadoServidor (int id, Socket cliente, PrivateKey privada) {
		this.id = id;
		this.cliente = cliente;
		this.privada = privada;
	}

	/*
	 * Metodo que inicia el thread
	 * Se encarga de realizar la comunicacion segura con el cliente
	*/
	@Override
	public void run() {
		try {
			outputStream = new DataOutputStream(this.cliente.getOutputStream());
			inputStream = new DataInputStream(this.cliente.getInputStream());
			long startTime = 0;

			// -- (Paso 1) El cliente envia un mensaje para iniciar la comunicacion segura --
			String[] partesPaso1 = inputStream.readUTF().split(",");
			if (!partesPaso1[0].equals("SECURE INIT")) {
				throw new Exception("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada al verificar inicio seguro");
			}

			// Paso 2
			// Se genera la firma digital del reto
			startTime = System.nanoTime();
			byte[] R1 = ManejadorDeCifrado.generarFirma(privada, new BigInteger(partesPaso1[1]).toByteArray());

			// Paso 3
			// Se envia la firma digital al cliente
			outputStream.writeUTF(Base64.getEncoder().encodeToString(R1));
			tiempoGenerarFirma += System.nanoTime() - startTime;

			// -- (Paso 4) El cliente verifica la firma digital del servidor --

			// -- (Paso 5) Se envia un mensaje al servidor para confirmar la validez de la firma --
			String mensajeErrorOk = inputStream.readUTF();
			if (!mensajeErrorOk.equals("OK")) {
				throw new Exception("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada al verificar R1");
			}

			// Paso 6
			// Se generan los valores de p, g, gx y vi, y se envian al cliente
			p = Servidor.getP();
			g = Servidor.getG();
			IvParameterSpec iv = generateIv();
			BigInteger x = new BigInteger(256, new SecureRandom());
			BigInteger gx = g.modPow(x, p);

			// Paso 7
			// Se envian los valores de p, g, gx y el vector de inicializacion al cliente
			outputStream.writeUTF(g.toString());
			outputStream.writeUTF(p.toString());
			outputStream.writeUTF(gx.toString());
			outputStream.writeUTF(Base64.getEncoder().encodeToString(iv.getIV()));
			
			// Tambien se envia la firma digital de los valores
			byte[] mensajeGenerado = (g.toString() + "," + p.toString() + "," + gx.toString()).getBytes();
			byte[] mensajeGeneradoCifrado = ManejadorDeCifrado.generarFirma(privada, mensajeGenerado);
			outputStream.writeUTF(Base64.getEncoder().encodeToString(mensajeGeneradoCifrado));

			// -- (Paso 8) El cliente verifica la firma digital de los valores recibidos --

			// Paso 9
			// Se revisa que todo este correcto
			mensajeErrorOk = inputStream.readUTF();
			if (!mensajeErrorOk.equals("OK")) {
				throw new Exception("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada al verificar G, P y G^X");
			}

			// -- (Paso 10) El cliente envia gy --
			BigInteger gy = new BigInteger(inputStream.readUTF());

			// -- (Paso 11a) El cliente genera las llaves simetricas K_AB1 y K_AB2 --

			// Paso 11b
			// Calcula (G^X)^Y
			byte[] z = gy.modPow(x, p).toByteArray();
			
			// Se generan las llaves simetricas K_AB1 y K_AB2
			SecretKey[] llaves = ManejadorDeCifrado.generarLlavesSimetricas(z);
			SecretKey K_AB1 = llaves[0];
			SecretKey K_AB2 = llaves[1];

			// Paso 12
			// Se envia un mensaje al cliente para confirmar la generacion de las llaves
			outputStream.writeUTF("CONTINUAR");

			// -- (Paso 13 y 14) El cliente envia el login y password cifrados --
			byte[] loginCifrado = Base64.getDecoder().decode(inputStream.readUTF());
			byte[] passwordCifrado = Base64.getDecoder().decode(inputStream.readUTF());

			// Paso 15
			// Se verifica el login y password del cliente
			String login = new String(ManejadorDeCifrado.descifrar(K_AB1, loginCifrado, iv));
			String password = new String(ManejadorDeCifrado.descifrar(K_AB1, passwordCifrado, iv));

			// Paso 16
			// Se envia un mensaje al cliente para confirmar la validez del login y password
			if (Servidor.consultarUsuario(login, password)) {
				outputStream.writeUTF("OK");
			} else {
				outputStream.writeUTF("ERROR");
				throw new Exception("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada al verificar usuario");
			}

			// -- (Paso 17 y 18) El servidor recibe la consulta con su HMAC
			startTime = System.nanoTime();
			byte[] consultaDescifrada = ManejadorDeCifrado.descifrar(K_AB1, Base64.getDecoder().decode(inputStream.readUTF()), iv);
			tiempoDescifrarConsulta += System.nanoTime() - startTime;
			startTime = System.nanoTime();
			byte[] hmacRecibido = Base64.getDecoder().decode(inputStream.readUTF());

			// Paso intermedio
			byte[] hmacGenerado = ManejadorDeCifrado.generarHMAC(K_AB2, consultaDescifrada);
			if (!MessageDigest.isEqual(hmacGenerado, hmacRecibido)) {
				outputStream.writeUTF("ERROR");
				throw new Exception("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada por error en el HMAC");
			}
			outputStream.writeUTF("OK");
			tiempoVerificarCodigo += System.nanoTime() - startTime;

			// Paso 19
			// Se envia la respuesta cifrada al cliente
			BigInteger consultaNumero = new BigInteger(consultaDescifrada);
			BigInteger respuesta = consultaNumero.subtract(BigInteger.ONE);
			byte[] respuestaCifrada = ManejadorDeCifrado.cifrar(K_AB1, respuesta.toByteArray(), iv);
			outputStream.writeUTF(Base64.getEncoder().encodeToString(respuestaCifrada));

			// Paso 20
			// Se envia el HMAC de la respuesta
			byte[] hmacRespuesta = ManejadorDeCifrado.generarHMAC(K_AB2, respuesta.toByteArray());
			outputStream.writeUTF(Base64.getEncoder().encodeToString(hmacRespuesta));
			

		} catch (Exception e) {
			System.out.println("DELEGADO " + id + ": Cerró la conexión con el cliente " + cliente.getRemoteSocketAddress() + " por error en la comunicacion");
			e.printStackTrace();
		} finally {
			try {
				if (outputStream != null) outputStream.close();
				if (inputStream != null) inputStream.close();
				if (cliente != null) cliente.close();
			}
			catch (IOException ioe) {
				ioe.printStackTrace();
			}
		}
		System.out.println("DELEGADO " + id + ": Ha finalizado");
	}

	/*
	 * Metodo que genera un vector de inicializacion para el CBC
	 * @return iv: Vector de inicializacion generado
	*/
	private IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	public static void imprimirTiempos() {
		System.out.println("Tiempos de ejecución para el servidor:");
		System.out.println();
		System.out.println("Tiempo de generación de firma: " + tiempoGenerarFirma / 1000000.0 + " ms");
		System.out.println("Tiempo de descifrado de consulta: " + tiempoDescifrarConsulta / 1000000.0 + " ms");
		System.out.println("Tiempo de verificación de código: " + tiempoVerificarCodigo / 1000000.0 + " ms");
	}

}
