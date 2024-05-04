package caso3;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Hashtable;

public class Vainas {
    private static final String rutaPyG = "datos/PG.in";
    private static final String rutaUsuarios = "datos/usuarios.in";

    private static BigInteger p;
    private static BigInteger g;
    private static Hashtable<String, String> usuarios = new Hashtable<String, String>();

    public static void main(String[] args) {
		leerPyG();
        leerUsuarios();
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

    private static void leerUsuarios() {
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
