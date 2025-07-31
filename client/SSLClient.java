package client;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.security.MessageDigest;

// import communication.*;
import encryption.*;

public class SSLClient {

    // Client Attributes
    private static ClientFactory clientFactory;
    private SSLSocket clientSocket;

    private String username;
    private String password;

    private String filesPath;
    private String groupsPath;

    private String privateKeyPath;
    private String publicKeysPath;

    private InputStream inStream;
    private OutputStream outStream;

    private DataInputStream in;
    private DataOutputStream out;

    // Constructor
    public SSLClient(String username, String password)
            throws NoSuchAlgorithmException, KeyManagementException, IOException {
        clientFactory = new ClientFactory(username, password);

        this.username = username;
        this.password = password;

        this.filesPath = "client_data/" + username + "/";
        this.groupsPath = "server_groups/";

        this.privateKeyPath = "resources/clients/" + username + "/" + username + "-private-key.pem";
        this.publicKeysPath = "resources/pubkeys/";
    }

    /**
     * Creates an Access Control List for the file
     * 
     * @param path        the path to the file
     * @param name        the name of the user
     * @param permissions the permissions for the user
     * @throws IOException
     */
    private void appendACL(String path, String name, String permissions) throws IOException {
        // If the file does not exist, create it
        File file = new File(path);
        if (!file.exists())
            file.createNewFile();

        try (BufferedReader reader = new BufferedReader(new FileReader(file));
                BufferedWriter writer = new BufferedWriter(new FileWriter(file, true))) {

            String line;
            boolean found = false;

            while ((line = reader.readLine()) != null) {
                if (line.startsWith(permissions)) {
                    // If the permissions already exist, append the user to the list
                    writer.write(line + "," + name);
                    writer.newLine();
                    found = true;
                    break;
                }
            }

            if (!found) {
                // If the permissions do not exist, create a new entry
                writer.write(permissions + "," + name);
                writer.newLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String[] readACL(String path) throws FileNotFoundException, IOException {
        String[] members = null;

        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(path)))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith("owner"))
                    continue;
                members = line.split(",");
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return members;
    }

    /**
     * Writes the received file data to a local file
     * 
     * @param path the path to the file
     * @throws FileNotFoundException
     * @throws IOException
     */
    private void writeToFile(String path, byte[] fileBytes) throws FileNotFoundException, IOException {
        // If the file does not exist, create it
        File file = new File(path);
        if (!file.exists())
            file.createNewFile();

        try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
            fileOutputStream.write(fileBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Reads a file into a byte array
     * 
     * @param path path to the file
     * @return byte array of the file, null if file not found
     * @throws Exception
     */
    private byte[] readFromFile(String path) throws FileNotFoundException, IOException {
        File file = new File(path);
        if (!file.exists())
            return null;

        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            return fileInputStream.readAllBytes();
        }
    }

    /**
     * Sends a file to the server as a three tuple, A UTF "header" srting, an integer representing the length of the
     * file, and the file bytes
     * 
     * @param filename  hashed filename
     * @param fileBytes file bytes
     * @throws Exception
     */
    private void send(String filename, byte[] fileBytes) throws Exception {
        out.writeUTF(filename);
        out.writeInt(fileBytes.length);
        out.write(fileBytes);
        out.flush();
    }

    // Send request
    private void send(String request) throws Exception {
        out.writeUTF(request);
        out.flush();
    }

    // Send filelength
    private void send(int filelength) throws Exception {
        out.writeInt(filelength);
        out.flush();
    }

    /**
     * Receives a file from the server, extracts first the length of the file, then the file bytes
     * 
     * @return file byte array
     * @throws Exception
     */
    private byte[] receive() throws Exception {
        int fileLength = in.readInt();
        System.out.println("File length: " + fileLength);

        if (fileLength == 0)
            System.out.println("File not found.");

        byte[] fileBytes = new byte[fileLength];
        in.readFully(fileBytes);
        System.out.println("File received.");

        return fileBytes;
    }

    /**
     * Converts a byte array to a hexadecimal string
     * 
     * @param bytes filename bytes
     * @return hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Hashes a string using SHA-256, files are hashed using the owner's username and password
     * 
     * @param input the string to hash
     * @return the hashed string
     */
    private String hashString(String filename, String name, String password) {
        try {
            String combined = name + password + filename;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(combined.getBytes());

            String hashString = bytesToHex(hashBytes);

            // String hashString = Base64.getEncoder().encodeToString(hashBytes);

            System.out.println("Hashed string: " + hashString);

            return hashString;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Uploads a file to the server
     * 
     * @param filename the name of the file
     * @throws Exception
     */
    private void uploadFile(String filename, String name, String password) throws Exception {
        String filePath = this.filesPath + filename;
        String ACLPath = this.filesPath + filename + ".acl";
        String publicKeyPath = this.publicKeysPath + name + "-public-key.pem";

        byte[] fileBytes = readFromFile(filePath);
        if (fileBytes == null) {
            System.out.println("File not found.");
            return;
        }

        if (password != null)
            appendACL(ACLPath, name, "owner"); // Owner supplies a password
        else
            appendACL(ACLPath, name, "shared"); // Shared files do not require a password

        SecretKey secretKey = AES.generateAESKey();
        byte[] iv = AES.generateIV();

        byte[] encryptedFileBytes = AES.encrypt(fileBytes, secretKey, iv);

        byte[] encryptedKey = RSA.encrypt(secretKey.getEncoded(), RSA.loadPublicKey(publicKeyPath));
        byte[] encryptedIV = RSA.encrypt(iv, RSA.loadPublicKey(publicKeyPath));

        send("UPLOAD");
        send(hashString(filename, name, password), encryptedFileBytes);

        send("UPLOAD");
        send(hashString("key-" + filename, name, password), encryptedKey);

        send("UPLOAD");
        send(hashString("iv-" + filename, name, password), encryptedIV);

        send("END");

        System.out.println("File uploaded successfully: " + filename);
    }

    /**
     * Downloads a file from the server, requests information about the file from the server, then decrypts the file
     * using the AES key and IV
     * 
     * @param filename the name of the file
     * @param name     the username of the owner
     * @param password the password of the owner
     * @throws Exception
     */
    private void downloadFile(String filename, String name, String password) throws Exception {
        String filePath = this.filesPath + filename;

        send("DOWNLOAD");
        send(hashString(filename, name, password));
        send(-1);

        byte[] encryptedFileBytes = receive();
        System.out.println("File received: " + new String(encryptedFileBytes));

        send("DOWNLOAD");
        send(hashString("key-" + filename, name, password));
        send(256);

        byte[] encryptedAESKey = receive();
        System.out.println("File received: " + new String(encryptedAESKey));

        send("DOWNLOAD");
        send(hashString("iv-" + filename, name, password));
        send(256);

        send("END");


        byte[] encryptedIV = receive();
        System.out.println("File received: " + new String(encryptedIV));

        byte[] aesKey = RSA.decrypt(encryptedAESKey, RSA.loadPrivateKey(privateKeyPath));
        byte[] iv = RSA.decrypt(encryptedIV, RSA.loadPrivateKey(privateKeyPath));

        SecretKey secretKey = new SecretKeySpec(aesKey, "AES");

        byte[] fileBytes = AES.decrypt(encryptedFileBytes, secretKey, iv);

        writeToFile(filePath, fileBytes);
        System.out.println("File downloaded successfully.");
    }

    /**
     * Shares a file with another user, uploads the file to the server with the other user's username
     * 
     * @param filename the name of the file
     * @param name     the username of the other user
     * @throws Exception
     */
    private void shareFile(String filename, String name) throws Exception {
        if (name.equals(username)) {
            System.out.println("Cannot share file with yourself.");
            return;
        }

        if (name.startsWith("group")) {
            String groupPath = this.groupsPath + name + ".csv";
            String[] members = readACL(groupPath);
            for (String member : members) {
                shareFile(filename, member);
            }
        }

        uploadFile(filename, name, null);
    }

    /**
     * Deletes a file from the server
     * 
     * @param filename
     * @throws Exception
     */
    private void deleteFile(String filename) throws Exception {
        String ACLPath = this.filesPath + filename + ".acl";

        revokeFile(filename, username, password);

        // Call revoke on all users who have access to the file
        String[] shared = readACL(ACLPath);
        for (int i = 1; i < shared.length; i++) {
            revokeFile(filename, shared[i], null);
        }

        File file = new File(ACLPath);
        if (file.exists()) {
            if (file.delete()) {
            System.out.println("File deleted successfully: " + ACLPath);
            } else {
            System.out.println("Failed to delete the file: " + ACLPath);
            }
        } else {
            System.out.println("File not found: " + ACLPath);
        }
    }

    /**
     * Revokes access to a file from a user
     * 
     * @param filename 
     * @param name 
     * @param password
     * @throws Exception
     */
    private void revokeFile(String filename, String name, String password) throws Exception {
        if (name.startsWith("group")) {
            String groupPath = this.groupsPath + name + ".csv";
            String[] members = readACL(groupPath);
            for (String member : members) {
                revokeFile(filename, member, null);
            }
        }

        send("REVOKE");
        send(hashString(filename, name, password));

        send("REVOKE");
        send(hashString("key-" + filename, name, password));

        send("REVOKE");
        send(hashString("iv-" + filename, name, password));
    }

    /**
     * Quits the client
     * 
     * @throws Exception
     */
    private void quit() throws Exception {
        send("QUIT");
        clientSocket.close();
    }

    /**
     * Creates a client instance
     * 
     * @throws Exception
     */
    private void createClientInstance() throws Exception {

        try {

            // Set up the SSL Context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(new KeyManager[] { clientFactory.getX509KeyManager() },
                    new TrustManager[] { clientFactory.getX509TrustManager() }, null);

            SSLSocketFactory socketFactory = sslContext.getSocketFactory();
            clientSocket = (SSLSocket) socketFactory.createSocket("localhost", 23068);
            clientSocket.setEnabledProtocols(new String[] { "TLSv1.3" });

            inStream = clientSocket.getInputStream();
            outStream = clientSocket.getOutputStream();

            in = new DataInputStream(inStream);
            out = new DataOutputStream(outStream);

            while (true) {
                // Send the command and filename
                System.out.println("\n");
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                System.out.print("Enter Command (UPLOAD/DOWNLOAD/SHARE/DELETE/REVOKE/QUIT): ");

                String request = reader.readLine().trim();
                String filename;
                String name;

                switch (request.toUpperCase()) {
                case "UPLOAD":
                    System.out.print("Enter Filename: ");
                    filename = reader.readLine().trim();
                    System.out.println("Uploading file: " + filename + " to server...");

                    uploadFile(filename, username, password);
                    break;
                case "DOWNLOAD":
                    System.out.print("Enter Filename: ");
                    filename = reader.readLine().trim();
                    System.out.println("Downloading file: " + filename + " from server...");

                    downloadFile(filename, username, password);
                    break;
                case "SHARE":
                    System.out.println("Enter Filename: ");
                    filename = reader.readLine().trim();
                    System.out.println("Enter username to share with: ");
                    name = reader.readLine().trim();
                    System.out.println("Sharing file: " + filename + " with user: " + name);

                    shareFile(filename, name);
                    break;
                case "DELETE":
                    System.out.println("Enter Filename: ");
                    filename = reader.readLine().trim();
                    System.out.println("Deleting file: " + filename + " from server...");

                    deleteFile(filename);
                    break;
                case "REVOKE":
                    System.out.println("Enter Filename: ");
                    filename = reader.readLine().trim();
                    System.out.println("Enter username to revoke access from: ");
                    name = reader.readLine().trim();
                    System.out.println("Revoking access to file: " + filename + " from user: " + name);

                    revokeFile(filename, name, null);
                    break;

                case "QUIT":
                    System.out.println("Quitting...");

                    quit();
                    return;
                default:
                    System.out.println("Invalid command.");
                    break;
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        String username = "client1";
        String password = "123456";
        SSLClient client = new SSLClient(username, password);
        client.createClientInstance();
    }

}
