package caso3;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

public class Servidor {

	private static final String generadorLlavePrivada = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCB5+rD/K7SOAlOhuECi4EB3wJs4VgMeAA1/D3KZ5jZg774OyKowUuo+n2HKF/2wT8vP+gFv4Sw/4Q92H3qR2Hw/1W30cng8Gp0jHdnqmxJYpefToOPg0gqdMK8nUf8Bs6NG6jI/07ot8hWmq4mmIqcIK6ugZIjou5qCIDZ/jAHkvZsaYlhqGrIaBTKzukUEW9hb42O8PguCzvb6RIhnSTCvqdFGvS1UZ6qWaXGK9tKevpk3kIMuMxIMbAVfosQ+IVIIOKb4zyovFEi3OZbdMpWw2eQiCSwk5UqcxrkE6eg//BtpG+c5+4lifjYAOeuujVt0NlyV5U/ZUAwgeGm+xaPAgMBAAECggEAeBWQuVdNq9pNECAyxA19VeN29HtizzPmzgC8hew6KWhWElVn9qOocy4K9/Pksc91vxHOQ/IEkTHCZwFHdFhEO2ltLZ1qhtr3LYHjpxqtOzE+g+8qQnHTNhv1IDIsJteL/HkDD7qikRHCyfv23IrKJwU3NO1l0Dd/ONlfcyQ79eMdXzRheBI83eDCIHs7gtGsyEzRyfZ/GKKuTN154CjxBkKVvGYWxVjp7WlytoHd9TlQqLDAMOJO1VkJhDP8i1lo4DkK9m6hd2lxIIg8QsfigkWnykNhRac1K3s4Az2lfVjh5ulQdV77E7gm6Mr/TqDyMnVlNvHihbc/xjjwHtqbQQKBgQC5rerPSTwxx+koIJ9LrRNk2aYo6TIv/F3RUbSc1frku8S6LnlKWNdVE7E6uxklSnCjPX6O6DE1hl53AUui4tAb+yPUP+ketSQPkiqHOYuxaw88ScpoMjH17pbP7bWF/xgw2Q9JqechDuB63DWDu08Mfspw+/AzX+hD5IhrLfX5EQKBgQCzGp/R0QKRfLT6tKjxSk2uEHJgrAgm9nfY95mmzhXgZSSWrXatS9aay9P3qmDxc2m0vnyOs7Xce3Wr19MQv+bT7tuO8L95NYdEQLuUim2GTlJroBNTPHNF/jkf6MMwiVPAW9obAqHOVhwSrDeIlsyTPu0FhWRTPtIKyN2WuVcVnwKBgHB8i08Op/fkizyzHq4C6Ufkj0QjmjL16YRAwnFtNLTTiCfetb4zuighaPISnPY5dal/PKeoxP8PKzVfRIombDs3VwpjuX/P70u7miYX16ghGrbEYWnkVt4Nr7HB6YGG/AnDxf4zfwFI+PeVZpoqpIYGXfA6wNbu2FAhJ//+dRBxAoGALIeEEMBsaQueW26rSkJ1Cb/hEBP1eupwZas5snUujznWXPgHt5JRau8eZkcgDyfosh1iDoCzyHuRiAYC3fk4RJzwTZuhn1slpFyLxqScEnZKm6OS6nDvIAnS3hIa5WhfQEYV9f0ziX9zP1k9/WGwvzM37tV5WhEWW8QRA7ZU5nUCgYBDFE3WMXLlW2ZN/WWNhXL7YBXwjRK8hX0Dk+O8EBFnblWJE2gYIsLmX1u+kQ/8Cr8I8cNFsojWqb+t1v503SSJjmSVG7SBl5U6660/PoCGHJop1piGdeB3SvOOUHK6z2KEzTyf+ddBsp20/F9oAr6Z738fdP+lnqGcPJJf2+JunA==";
	private PrivateKey privada;
	private int puerto;

	public Servidor(int puerto) throws InvalidKeySpecException, NoSuchAlgorithmException {
		this.puerto = puerto;
		this.privada = ManejadorDeCifrado.generarLlavePrivada(generadorLlavePrivada);
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
			while (true) {
				Socket nuevaSolicitud = conexion.accept();
				DelegadoServidor delegado = new DelegadoServidor(nuevaSolicitud, this.privada);
				delegado.start();
			}
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		finally {
			// Se cierra el socket del servidor si se produce una excepcion
			System.out.println("Servidor cerrado correctamente");
			if (conexion != null) {
				try {
					conexion.close();
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			}
		}
	}


	/*
	 * Metodo que inicia el servidor
	 * Inicia el servidor en el puerto especificado
	*/
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
		Servidor servidor = new Servidor(4000);
		servidor.iniciar();
	}
}
