import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Scanner;

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
            generateKeys(userId);

            try (Socket socket = new Socket(host, port);
                 DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                 DataInputStream dis = new DataInputStream(socket.getInputStream());
                 Scanner scanner = new Scanner(System.in)) {

                // Send user ID
                dos.writeUTF(userId);

                // Receive number of messages
                int numMessages = dis.readInt();
                System.out.println("There are " + numMessages + " message(s) for you:");

                for (int i = 0; i < numMessages; i++) {
                    String message = dis.readUTF();
                    System.out.println(message);
                }

                // Ask user whether they want to send a message
                String response;
                do {
                    System.out.println("Do you want to send a message? (yes/no)");
                    response = scanner.nextLine();
                    if ("yes".equalsIgnoreCase(response)) {
                        // Prompt user to enter recipient userid
                        System.out.println("Enter recipient userid:");
                        String recipientUserId = scanner.nextLine();

                        // Compare userIDs directly
                        if (recipientUserId.equalsIgnoreCase(userId)) {
                            System.out.println("You cannot send a message to yourself.");
                            continue;
                        }

                        System.out.println("Enter message:");
                        String message = scanner.nextLine();

                        // Send recipient userid, timestamp, and message to server
                        dos.writeUTF(userId); // Sender's ID
                        dos.writeUTF(recipientUserId);
                        dos.writeLong(new Date().getTime());
                        dos.writeUTF(message);
                        dos.writeInt(signMessage(message, userId).length);
                        dos.write(signMessage(message, userId));
                    }
                } while ("yes".equalsIgnoreCase(response));

                // Send "exit" to the server to indicate client wants to exit
                dos.writeUTF("exit");

                // Close the socket after sending "exit"
                socket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void generateKeys(String userId) {
        try {
            File pubKeyFile = new File(userId + ".pub");
            File prvKeyFile = new File(userId + ".prv");

            if (!pubKeyFile.exists() || !prvKeyFile.exists()) {
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

            try (FileOutputStream fos = new FileOutputStream(userId + ".pub")) {
                fos.write(kp.getPublic().getEncoded());
            }

            try (FileOutputStream fos = new FileOutputStream(userId + ".prv")) {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());
                fos.write(pkcs8EncodedKeySpec.getEncoded());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] signMessage(String message, String userId) {
        try {
            File prvKeyFile = new File(userId + ".prv");
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(readKeyBytes(prvKeyFile)));

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes(StandardCharsets.UTF_8));
            return signature.sign();
        } catch (Exception e) {
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
