import javax.crypto.Cipher;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Client {

    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Usage: java Client host port userid");
            return;
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2];

        try {
            // Generate keys if not exist
            generateKeys(userId);

            Socket socket = new Socket(host, port);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            DataInputStream dis = new DataInputStream(socket.getInputStream());

            dos.writeUTF(userId);

            // Load user's private key
            FileInputStream fis = new FileInputStream(userId + ".prv");
            byte[] prvKeyBytes = new byte[fis.available()];
            fis.read(prvKeyBytes);
            fis.close();
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(prvKeyBytes));

            // Load server's public key
            fis = new FileInputStream("server.pub");
            byte[] serverPubKeyBytes = new byte[fis.available()];
            fis.read(serverPubKeyBytes);
            fis.close();
            PublicKey serverPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(serverPubKeyBytes));

            // Send encrypted message
            sendMessage(socket, serverPublicKey, "Hello, server!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void generateKeys(String userId) {
        try {
            // Check if keys already exist
            File pubKeyFile = new File(userId + ".pub");
            File prvKeyFile = new File(userId + ".prv");

            if (!pubKeyFile.exists() || !prvKeyFile.exists()) {
                // Keys do not exist, generate them
                System.out.println("Generating keys for user: " + userId);
                generateKeysInternal(userId);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void generateKeysInternal(String userId) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();

            // Save public key
            try (FileOutputStream fos = new FileOutputStream(userId + ".pub")) {
                fos.write(kp.getPublic().getEncoded());
            }

            // Save private key in PKCS#8 format
            try (FileOutputStream fos = new FileOutputStream(userId + ".prv")) {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());
                fos.write(pkcs8EncodedKeySpec.getEncoded());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendMessage(Socket socket, PublicKey publicKey, String message) throws Exception {
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

        // Encrypt message
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        // Send encrypted message
        dos.writeInt(encryptedMessage.length);
        dos.write(encryptedMessage);
    }
}
