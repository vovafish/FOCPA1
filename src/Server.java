import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
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

    private static void handleClient(Socket socket) {
        try (DataInputStream dis = new DataInputStream(socket.getInputStream());
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

            String userId = dis.readUTF();
            System.out.println("User connected: " + userId);

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
                        System.out.println("User disconnected: " + userId);
                        socket.close();
                        break;
                    }

                    String recipientUserId = dis.readUTF();
                    long timestamp = dis.readLong();
                    String message = dis.readUTF();

                    synchronized (messagesLock) {
                        List<String> recipientMessages = messages.getOrDefault(recipientUserId, new ArrayList<>());
                        recipientMessages.add(new Date(timestamp) + "\nMessage: " + message);
                        messages.put(recipientUserId, recipientMessages);
                    }

                    // Modified output for server console
                    System.out.println("Incoming message from " + senderUserId + "\n"
                            + new Date(timestamp) + "\nRecipient: " + recipientUserId + "\nMessage: " + message);

                    // Send message to the client without recipient information
                    dos.writeUTF(new Date(timestamp) + "\nMessage: " + message);

                } catch (EOFException e) {
                    // The client has closed the connection
                    System.out.println("User disconnected: " + userId);
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
