import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

public class Server {

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java Server port");
            return;
        }

        int port = Integer.parseInt(args[0]);

        try {
            // Generate keys if not exist
            generateKeys();

            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server is running and waiting for incoming connections...");

            while (true) {
                try (Socket socket = serverSocket.accept()) {
                    handleClient(socket);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void generateKeys() {
        try {
            // Check if keys already exist
            File pubKeyFile = new File("server.pub");
            File prvKeyFile = new File("server.prv");

            if (!pubKeyFile.exists() || !prvKeyFile.exists()) {
                // Keys do not exist, generate them
                System.out.println("Generating keys for server");
                generateKeysInternal();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void generateKeysInternal() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();

            // Save public key
            try (FileOutputStream fos = new FileOutputStream("server.pub")) {
                fos.write(kp.getPublic().getEncoded());
            }

            // Save private key in PKCS#8 format
            try (FileOutputStream fos = new FileOutputStream("server.prv")) {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());
                fos.write(pkcs8EncodedKeySpec.getEncoded());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket) throws Exception {
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

        String userId = dis.readUTF();
        System.out.println("User connected: " + userId);

        // Load server's private key
        FileInputStream fis = new FileInputStream("server.prv");
        byte[] prvKeyBytes = new byte[fis.available()];
        fis.read(prvKeyBytes);
        fis.close();
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(prvKeyBytes));

        // Receive encrypted message
        int length = dis.readInt();
        if(length > 0) {
            byte[] encryptedMessage = new byte[length];
            dis.readFully(encryptedMessage, 0, encryptedMessage.length);

            // Decrypt message
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedMessage = cipher.doFinal(encryptedMessage);

            System.out.println("Received message: " + new String(decryptedMessage, StandardCharsets.UTF_8));
        }
    }
}
