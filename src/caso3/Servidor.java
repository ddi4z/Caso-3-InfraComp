package caso3;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Random;
import java.util.Scanner;

public class Servidor {

	private static final String generadorLlavePrivada = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCB5+rD/K7SOAlOhuECi4EB3wJs4VgMeAA1/D3KZ5jZg774OyKowUuo+n2HKF/2wT8vP+gFv4Sw/4Q92H3qR2Hw/1W30cng8Gp0jHdnqmxJYpefToOPg0gqdMK8nUf8Bs6NG6jI/07ot8hWmq4mmIqcIK6ugZIjou5qCIDZ/jAHkvZsaYlhqGrIaBTKzukUEW9hb42O8PguCzvb6RIhnSTCvqdFGvS1UZ6qWaXGK9tKevpk3kIMuMxIMbAVfosQ+IVIIOKb4zyovFEi3OZbdMpWw2eQiCSwk5UqcxrkE6eg//BtpG+c5+4lifjYAOeuujVt0NlyV5U/ZUAwgeGm+xaPAgMBAAECggEAeBWQuVdNq9pNECAyxA19VeN29HtizzPmzgC8hew6KWhWElVn9qOocy4K9/Pksc91vxHOQ/IEkTHCZwFHdFhEO2ltLZ1qhtr3LYHjpxqtOzE+g+8qQnHTNhv1IDIsJteL/HkDD7qikRHCyfv23IrKJwU3NO1l0Dd/ONlfcyQ79eMdXzRheBI83eDCIHs7gtGsyEzRyfZ/GKKuTN154CjxBkKVvGYWxVjp7WlytoHd9TlQqLDAMOJO1VkJhDP8i1lo4DkK9m6hd2lxIIg8QsfigkWnykNhRac1K3s4Az2lfVjh5ulQdV77E7gm6Mr/TqDyMnVlNvHihbc/xjjwHtqbQQKBgQC5rerPSTwxx+koIJ9LrRNk2aYo6TIv/F3RUbSc1frku8S6LnlKWNdVE7E6uxklSnCjPX6O6DE1hl53AUui4tAb+yPUP+ketSQPkiqHOYuxaw88ScpoMjH17pbP7bWF/xgw2Q9JqechDuB63DWDu08Mfspw+/AzX+hD5IhrLfX5EQKBgQCzGp/R0QKRfLT6tKjxSk2uEHJgrAgm9nfY95mmzhXgZSSWrXatS9aay9P3qmDxc2m0vnyOs7Xce3Wr19MQv+bT7tuO8L95NYdEQLuUim2GTlJroBNTPHNF/jkf6MMwiVPAW9obAqHOVhwSrDeIlsyTPu0FhWRTPtIKyN2WuVcVnwKBgHB8i08Op/fkizyzHq4C6Ufkj0QjmjL16YRAwnFtNLTTiCfetb4zuighaPISnPY5dal/PKeoxP8PKzVfRIombDs3VwpjuX/P70u7miYX16ghGrbEYWnkVt4Nr7HB6YGG/AnDxf4zfwFI+PeVZpoqpIYGXfA6wNbu2FAhJ//+dRBxAoGALIeEEMBsaQueW26rSkJ1Cb/hEBP1eupwZas5snUujznWXPgHt5JRau8eZkcgDyfosh1iDoCzyHuRiAYC3fk4RJzwTZuhn1slpFyLxqScEnZKm6OS6nDvIAnS3hIa5WhfQEYV9f0ziX9zP1k9/WGwvzM37tV5WhEWW8QRA7ZU5nUCgYBDFE3WMXLlW2ZN/WWNhXL7YBXwjRK8hX0Dk+O8EBFnblWJE2gYIsLmX1u+kQ/8Cr8I8cNFsojWqb+t1v503SSJjmSVG7SBl5U6660/PoCGHJop1piGdeB3SvOOUHK6z2KEzTyf+ddBsp20/F9oAr6Z738fdP+lnqGcPJJf2+JunA==";
	private PrivateKey privada;
	private int puerto;
    private static int cantidadClientes;

	private static final String rutaPyG = "datos/PG.in";
    private static final String rutaUsuarios = "datos/usuarios.in";
    private static BigInteger p;
    private static BigInteger g;
    private static Hashtable<String, String> usuarios = new Hashtable<String, String>();

	private static ArrayList<Cliente> clientes = new ArrayList<Cliente>();
	private static ArrayList<DelegadoServidor> delegados = new ArrayList<DelegadoServidor>();

	public Servidor(int puerto) throws InvalidKeySpecException, NoSuchAlgorithmException {
		this.puerto = puerto;
		this.privada = ManejadorDeCifrado.generarLlavePrivada(generadorLlavePrivada);
		leerPyG();
		leerUsuarios();
	}

	/*
	 * Metodo que inicia el servidor
	 * Inicia el servidor en el puerto especificado
	*/
	public void iniciar() {
		ServerSocket conexion = null;
		try {
			// Se crea el socket del servidor
			// En el bucle se crea un nuevo thread para cada cliente nuevo
			// El servidor se queda esperando nuevas conexiones
			conexion = new ServerSocket(this.puerto);
			System.out.println("Esperando conexiones en el puerto " + this.puerto);
			Socket nuevaSolicitud;
			DelegadoServidor delegado;
			Cliente cliente;
			for (int i = 0; i < cantidadClientes; i++){
				cliente = new Cliente(i);
				clientes.add(cliente);
				cliente.start();
				nuevaSolicitud = conexion.accept();
				delegado = new DelegadoServidor(i, nuevaSolicitud, this.privada);
				delegados.add(delegado);
				delegado.start();
			}

			for (Cliente c : clientes) {
				c.join();
			}

			for (DelegadoServidor d : delegados) {
				d.join();
			}
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		} finally {
			// Se cierra el socket del servidor si se produce una excepcion
			if (conexion != null) {
				try {
					conexion.close();
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
			System.out.println("Servidor cerrado correctamente");
		}
	}

	/*
	 * Metodo que inicia el servidor
	 * Inicia el servidor en el puerto especificado
	*/
	public static void main(String[] args) {
		try {
			Servidor servidor = new Servidor(4000);
			Scanner sc = new Scanner(System.in);
			System.out.println("******************************************");
			System.out.println("¡Bienvenido!");
			System.out.println("Escriba la cantidad de clientes:");
			cantidadClientes = Integer.parseInt(sc.nextLine());
			sc.close();
			System.out.println("******************************************");

			servidor.iniciar();
			System.out.println();
			System.out.println("******************************************");
			Cliente.imprimirTiempos();
			System.out.println();
			DelegadoServidor.imprimirTiempos();
			System.out.println("******************************************");
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
		/*
	 * Metodo que lee los valores de p y g del archivo PG.in
	*/
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

	/*
	 * Metodo que lee los usuarios del archivo usuarios.in
	*/
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

	public static BigInteger getP() {
		return p;
	}

    public static BigInteger getG() {
        return g;
    }

	public static boolean consultarUsuario(String login, String password) {
		return usuarios.containsKey(login) && usuarios.get(login).equals(password);
	}

	public static String[] obtenerUsuarioRandom() {
		ArrayList<String> logins = new ArrayList<String>(usuarios.keySet());
		Random random = new Random();
		int i = random.nextInt(logins.size());
		String login = logins.get(i);
		String password = usuarios.get(login);
		return new String[] {login, password};
	}

}
