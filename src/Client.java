import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;

public class Client {
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java Client host port userid");
            return;
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2];

        try (Socket socket = new Socket(host, port);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream())) {

            dos.writeUTF(userId);

            // Your secure communication logic here
            // (e.g., sending and receiving encrypted messages)

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
