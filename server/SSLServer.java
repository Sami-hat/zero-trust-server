package server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.xml.crypto.Data;

import java.nio.file.Files;
import java.nio.file.Paths;

@SuppressWarnings("unused")

public class SSLServer {

    // Server Attributes
    private ServerFactory serverFactory;
    private SSLServerSocket serverSocket;

    // File path
    private String filesPath;

    public SSLServer() {
        serverFactory = new ServerFactory();
        this.filesPath = "server_data/";
    }

    /**
     * Writes the received file data to a local file
     * 
     * @param path      the path to the file
     * @param fileBytes the byte array of the file
     * @throws FileNotFoundException
     * @throws IOException
     */
    private void writeToFile(String path, byte[] fileBytes) throws FileNotFoundException, IOException {
        // If the file does not exist, create it
        System.out.println("Writing file to: " + path);

        File file = new File(path);
        if (!file.exists()) {
            System.out.println("Creating file...");
            file.createNewFile();
        } else {
            System.out.println("File already exists. Overwriting...");
        }

        try (FileOutputStream fileOutputStream = new FileOutputStream(file)) {
            fileOutputStream.write(fileBytes);
        } catch (IOException e) {
            System.out.println("Error writing to file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Reads a file into a byte array
     * 
     * @param path     path to the file
     * @param filesize the (expected) size of the file
     * @return byte array of the file, null if file not found
     * @throws Exception
     */
    private byte[] readFromFile(String path, int filesize) throws FileNotFoundException, IOException {
        return Files.readAllBytes(Paths.get(path));
    }

    /**
     * Uploads a file to the server
     * 
     * @param in input stream
     * @throws Exception
     */
    private void upload(DataInputStream in) throws Exception {
        String filename = in.readUTF();
        System.out.println("Uploading file: " + filename);

        int filelength = in.readInt();
        System.out.println("File length: " + filelength);

        byte[] fileBytes = new byte[filelength];
        in.read(fileBytes);

        String path = this.filesPath + filename;

        writeToFile(path, fileBytes);

        return;
    }

    /**
     * Deletes a file from the server
     * 
     * @throws Exception
     */
    private void delete(DataInputStream in) throws Exception {
        String filename = in.readUTF();
        System.out.println("Deleting file: " + filename);

        String path = this.filesPath + filename;

        File file = new File(path);
        if (file.exists()) {
            file.delete();
            System.out.println("File deleted.");
        } else {
            System.out.println("File not found.");
        }

        return;
    }

    /**
     * Downloads a file from the server
     * 
     * @param in  input stream
     * @param out output stream
     * @throws Exception
     */
    private void download(DataInputStream in, DataOutputStream out) throws Exception {
        String filename = in.readUTF();
        int filesize = in.readInt();

        String path = this.filesPath + filename;

        System.out.println("Downloading file at: " + path);

        byte[] fileBytes = readFromFile(path, filesize);
        System.out.println("File bytes: " + fileBytes.length);

        out.writeInt(fileBytes.length);
        out.write(fileBytes);
        out.flush();
    }

    /**
     * Creates an instance of the server
     * 
     * @throws Exception
     */
    private void createServerInstance() throws Exception {

        try {
            // Set up the SSL Context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(new KeyManager[] { serverFactory.getX509KeyManager() },
                    new TrustManager[] { serverFactory.getX509TrustManager() }, null);

            SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
            serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(23068);
            serverSocket.setNeedClientAuth(true);
            serverSocket.setEnabledProtocols(new String[] { "TLSv1.3" });
            System.out.println("Server listening...");

            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
            // Create input and output streams
            InputStream inputStream = clientSocket.getInputStream();
            OutputStream outputStream = clientSocket.getOutputStream();

            DataInputStream in = new DataInputStream(inputStream);
            DataOutputStream out = new DataOutputStream(outputStream);
            
            while (true) {

                String request = in.readUTF();
                System.out.println("Request: " + request);

                // Handle request
                switch (request.toUpperCase()) {
                case "UPLOAD":
                    upload(in);
                    break;
                case "DOWNLOAD":
                    download(in, out);
                    break;
                case "DELETE":
                    delete(in);
                case "END":
                    System.out.println("Operation ended.");
                    break;
                case "QUIT":
                    System.out.println("Client disconnected.");

                    in.close();
                    out.close();

                    inputStream.close();
                    outputStream.close();

                    clientSocket.close();
                    return;
                default:
                    System.out.println("Invalid request type.");
                    break;
                }
            }

        } catch (FileNotFoundException e) {
            System.err.println("File not found: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("I/O error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        SSLServer server = new SSLServer();
        server.createServerInstance();
    }
}
