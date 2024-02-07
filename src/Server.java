import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Server {
    private static Map<String, List<String>> messages = new HashMap<>();
    private static Object messagesLock = new Object(); // Added for thread safety

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java Server port");
            return;
        }
        int port = Integer.parseInt(args[0]);
        try {
            generateKeys();
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Server is running and waiting for incoming connections...");
            while (true) {
                try {
                    Socket socket = serverSocket.accept();
                    new Thread(() -> {
                        try {
                            handleClient(socket);
                        } catch (EOFException eof) {
                            // Client disconnected unexpectedly
                            System.out.println("Client disconnected unexpectedly.");
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }).start();
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
            File pubKeyFile = new File("server.pub");
            File prvKeyFile = new File("server.prv");

            if (!pubKeyFile.exists() || !prvKeyFile.exists()) {
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

            try (FileOutputStream fos = new FileOutputStream("server.pub")) {
                fos.write(kp.getPublic().getEncoded());
            }

            try (FileOutputStream fos = new FileOutputStream("server.prv")) {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());
                fos.write(pkcs8EncodedKeySpec.getEncoded());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void handleClient(Socket socket) throws IOException {
        try (DataInputStream dis = new DataInputStream(socket.getInputStream());
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

            String userId = dis.readUTF();
            String hashedUserId = hashUserId(userId); // Hash the user ID
            System.out.println("User connected: " + hashedUserId);

            synchronized (messagesLock) {
                List<String> userMessages = messages.getOrDefault(userId, new ArrayList<>());
                dos.writeInt(userMessages.size());

                for (String message : userMessages) {
                    dos.writeUTF(message);
                }
            }

            while (true) {
                try {
                    String senderUserId = dis.readUTF();
                    if ("exit".equalsIgnoreCase(senderUserId)) {
                        // If the client sends "exit," close the connection
                        System.out.println("User disconnected: " + hashedUserId);
                        socket.close();
                        break;
                    }

                    String recipientUserId = dis.readUTF();
                    long timestamp = dis.readLong();
                    String encryptedMessage = dis.readUTF();

                    // Decrypting the received message
                    String decryptedMessage = decryptMessage(encryptedMessage);
                    if (decryptedMessage != null) {
                        synchronized (messagesLock) {
                            List<String> recipientMessages = messages.getOrDefault(recipientUserId, new ArrayList<>());
                            recipientMessages.add(new Date(timestamp) + "\nMessage: " + decryptedMessage);
                            messages.put(recipientUserId, recipientMessages);
                        }

                        // Modified output for server console
                        System.out.println("Incoming message from " + userId + "\n"
                                + new Date(timestamp) + "\nRecipient: " + recipientUserId + "\nDecrypted Message: " + decryptedMessage);

                        // Send acknowledgment to the client
                        dos.writeUTF("Message received and decrypted successfully.");
                    } else {
                        System.out.println("Message decryption failed for message from user: " + senderUserId);
                    }
                } catch (EOFException e) {
                    // The client has closed the connection
                    System.out.println("User disconnected: " + hashedUserId);
                    socket.close();
                    break;
                }
            }
        }
    }

    private static String decryptMessage(String encryptedMessage) {
        try {
            File prvKeyFile = new File("server.prv");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(readKeyBytes(prvKeyFile)));

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String hashUserId(String userId) {
        try {
            String secret = "gfhk2024:";
            String userIdWithSecret = secret + userId; // Prepend the secret string to the user ID
            MessageDigest md = MessageDigest.getInstance("MD5"); // Get MD5 message digest instance
            byte[] hashBytes = md.digest(userIdWithSecret.getBytes(StandardCharsets.UTF_8)); // Compute the hash
            // Convert byte array to hexadecimal string
            BigInteger number = new BigInteger(1, hashBytes);
            StringBuilder hexString = new StringBuilder(number.toString(16));
            // Pad with leading zeros to ensure 32-bit length
            while (hexString.length() < 32) {
                hexString.insert(0, '0');
            }
            return hexString.toString(); // Return the hashed user ID
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] readKeyBytes(File keyFile) throws IOException {
        try (FileInputStream fis = new FileInputStream(keyFile)) {
            return fis.readAllBytes();
        }
    }
}
