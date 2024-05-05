package caso3;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.Hashtable;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ThreadCliente extends Thread {

	private Socket cliente = null;
	private DataOutputStream outputStream = null;
	private DataInputStream inputStream = null;
	private boolean parar = false;
	private PrivateKey privada;
	private static final String rutaPyG = "datos/PG.in";
    private static final String rutaUsuarios = "datos/usuarios.in";
    private static BigInteger p;
    private static BigInteger g;
    private static Hashtable<String, String> usuarios = new Hashtable<String, String>();

	public ThreadCliente(Socket cliente, PrivateKey privada) {
		this.cliente = cliente;
		this.privada = privada;
	}


	public void run() {
		try {
			outputStream = new DataOutputStream(this.cliente.getOutputStream());
			inputStream = new DataInputStream(this.cliente.getInputStream());

			while (!parar) {

				// Paso 2
				String[] partesPaso1 = inputStream.readUTF().split(",");
				if (!partesPaso1[0].equals("SECURE INIT")) {
					System.out.println("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada al verificar inicio seguro");
					parar = true;
					continue;
				}

				Signature signature = Signature.getInstance("SHA256withRSA");
				signature.initSign(privada);
				signature.update(new BigInteger(partesPaso1[1]).toByteArray());
				byte[] R1 = signature.sign();

				outputStream.writeUTF(Base64.getEncoder().encodeToString(R1));

				// Paso 5
				String mensajeErrorOk = inputStream.readUTF();
				if (!mensajeErrorOk.equals("OK")) {
					System.out.println("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada al verificar R1");
					parar = true;
					continue;
				}
				// Paso 6
				leerPyG();

				// Paso 7
				BigInteger x = new BigInteger(256, new SecureRandom());
				BigInteger gx = g.modPow(x, p);
				String mensajePGX = g.toString() + "," + p.toString() + "," + gx.toString();
				signature = Signature.getInstance("SHA256withRSA");
				signature.initSign(privada);
				signature.update(mensajePGX.getBytes());
				byte[] PGXBytes = signature.sign();

				outputStream.writeUTF(g.toString());
				outputStream.writeUTF(p.toString());
				outputStream.writeUTF(gx.toString());
				IvParameterSpec iv = generateIv();
				outputStream.writeUTF(Base64.getEncoder().encodeToString(iv.getIV()));
				outputStream.writeUTF(Base64.getEncoder().encodeToString(PGXBytes));

				mensajeErrorOk = inputStream.readUTF();
				if (!mensajeErrorOk.equals("OK")) {
					System.out.println("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada al verificar PGX");
					parar = true;
					continue;
				}

				BigInteger gy = new BigInteger(inputStream.readUTF());
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


				outputStream.writeUTF("CONTINUAR");

				leerUsuarios();
				byte[] loginCifrado = Base64.getDecoder().decode(inputStream.readUTF());
				byte[] passwordCifrado = Base64.getDecoder().decode(inputStream.readUTF());
				
				String login = new String(CifradoSimetrico.descifrar(key1, loginCifrado, iv));
				String password = new String(CifradoSimetrico.descifrar(key1, passwordCifrado, iv));


				if (usuarios.containsKey(login) && usuarios.get(login).equals(password)) {
					outputStream.writeUTF("OK");
				} else {
					outputStream.writeUTF("ERROR");
					System.out.println("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada al verificar usuario");
					parar = true;
					continue;
				}





				byte[] consultaDescifrada = CifradoSimetrico.descifrar(key1, Base64.getDecoder().decode(inputStream.readUTF()), iv);
				byte[] hmacGenerado = CifradoSimetrico.generarHMAC(key2, consultaDescifrada);
				byte[] hmac = Base64.getDecoder().decode(inputStream.readUTF());

				BigInteger consulta = new BigInteger(consultaDescifrada);



				if (!MessageDigest.isEqual(hmacGenerado, hmac)) {
					System.out.println("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada por error en el HMAC");
					outputStream.writeUTF("ERROR");
					parar = true;
					continue;
				}
				outputStream.writeUTF("OK");

				BigInteger respuesta = consulta.subtract(BigInteger.ONE);
				byte[] respuestaCifrada = CifradoSimetrico.cifrar(key1, respuesta.toByteArray(), iv);
				byte[] hmacRespuesta = CifradoSimetrico.generarHMAC(key2, respuesta.toByteArray());

				outputStream.writeUTF(Base64.getEncoder().encodeToString(respuestaCifrada));
				outputStream.writeUTF(Base64.getEncoder().encodeToString(hmacRespuesta));
			}

		} catch (Exception e) {
			System.out.println("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada por error en la comunicacion");
		}finally {
			parar();
		}

		System.out.println("Thread finalizado");

	}

	private void parar() {
		parar = true;
		try {
			if (outputStream != null) {
				outputStream.close();
			}

			if (inputStream != null) {
				inputStream.close();
			}

			if (cliente != null) {
				cliente.close();
			}
		}catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}

	private IvParameterSpec generateIv() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		return new IvParameterSpec(iv);
	}

	private static void leerPyG() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(rutaPyG));
            String linea = "";
            linea = br.readLine();
            p = new BigInteger(linea, 16);
            linea = br.readLine();
            g = new BigInteger(linea, 16);
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void leerUsuarios() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(rutaUsuarios));
            String linea = "";
            while ((linea = br.readLine()) != null) {
                String[] partes = linea.split(":");
                String login = partes[0];
                String password = partes[1];
                usuarios.put(login, password);
            }
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
