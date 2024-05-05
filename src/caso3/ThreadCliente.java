package caso3;


import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.Hashtable;

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
					System.out.println("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada");
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
					System.out.println("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada");
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
				outputStream.writeUTF(Base64.getEncoder().encodeToString(PGXBytes));

				mensajeErrorOk = inputStream.readUTF();
				if (!mensajeErrorOk.equals("OK")) {
					System.out.println("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada");
					parar = true;
					continue;
				}



				BigInteger consulta = new BigInteger(inputStream.readUTF());
				System.out.println(consulta);

				StringBuilder respuesta = new StringBuilder();
				respuesta.append(consulta.subtract(BigInteger.ONE));
				outputStream.writeUTF(respuesta.toString());
			}

		} catch (Exception e) {
			System.out.println("Conexion con cliente: " + cliente.getRemoteSocketAddress() + " cerrada");
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

	private static void leerPyG() {
        try {
            BufferedReader br = new BufferedReader(new FileReader(rutaPyG));
            String linea = "";
            linea = br.readLine();
            p = new BigInteger(linea, 16);
            System.out.println("p: " + p);
            linea = br.readLine();
            g = new BigInteger(linea, 16);
            System.out.println("g: " + g);
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
            System.out.println(usuarios);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
