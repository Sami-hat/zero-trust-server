package server;

import java.io.*;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.*;
import javax.net.ssl.*;

public class SSLServer {
    private static final Logger logger = Logger.getLogger(SSLServer.class.getName());

    // Configuration constants
    private static final int PORT = 23068;
    private static final int THREAD_POOL_SIZE = 10;
    private static final int MAX_PENDING_CONNECTIONS = 50;
    private static final int CLIENT_TIMEOUT = 300000; // 5 minutes
    private static final String FILES_PATH = "server_data/";

    private final ServerFactory serverFactory;
    private SSLServerSocket serverSocket;
    private final ExecutorService executorService;
    private final AtomicBoolean isRunning;
    private final ConcurrentHashMap<String, Object> fileLocks;

    public SSLServer() {
        this.serverFactory = new ServerFactory();
        this.executorService = new ThreadPoolExecutor(
                THREAD_POOL_SIZE,
                THREAD_POOL_SIZE * 2,
                60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(MAX_PENDING_CONNECTIONS),
                new ThreadFactory() {
                    private int count = 0;

                    @Override
                    public Thread newThread(Runnable r) {
                        Thread t = new Thread(r, "SSLServer-Worker-" + count++);
                        t.setDaemon(true);
                        return t;
                    }
                },
                new ThreadPoolExecutor.CallerRunsPolicy());
        this.isRunning = new AtomicBoolean(false);
        this.fileLocks = new ConcurrentHashMap<>();

        // Setup logging
        setupLogging();

        // Ensure server data directory exists
        createServerDataDirectory();
    }

    private void setupLogging() {
        try {
            FileHandler fileHandler = new FileHandler("server.log", true);
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
            logger.setLevel(Level.INFO);
        } catch (IOException e) {
            logger.severe("Failed to setup logging: " + e.getMessage());
        }
    }

    private void createServerDataDirectory() {
        File dir = new File(FILES_PATH);
        if (!dir.exists()) {
            if (!dir.mkdirs()) {
                logger.severe("Failed to create server data directory");
                throw new RuntimeException("Cannot create server data directory");
            }
        }
    }

    public void start() throws Exception {
        if (isRunning.get()) {
            throw new IllegalStateException("Server is already running");
        }

        try {
            // Set up SSL Context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(
                    new KeyManager[] { serverFactory.getX509KeyManager() },
                    new TrustManager[] { serverFactory.getX509TrustManager() },
                    new SecureRandom());

            SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();
            serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(PORT);
            serverSocket.setNeedClientAuth(true);
            serverSocket.setEnabledProtocols(new String[] { "TLSv1.3" });
            serverSocket.setSoTimeout(1000); // 1 second timeout for accept()

            isRunning.set(true);
            logger.info("Server started on port " + PORT);

            // Start accepting connections
            acceptConnections();

        } catch (Exception e) {
            logger.severe("Failed to start server: " + e.getMessage());
            throw e;
        }
    }

    private void acceptConnections() {
        while (isRunning.get()) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                clientSocket.setSoTimeout(CLIENT_TIMEOUT);

                String clientInfo = clientSocket.getInetAddress().getHostAddress() +
                        ":" + clientSocket.getPort();
                logger.info("New connection from " + clientInfo);

                // Handle client in a separate thread
                executorService.submit(new ClientHandler(clientSocket, clientInfo));

            } catch (SocketTimeoutException e) {
                // This is expected, allows checking isRunning flag
                continue;
            } catch (IOException e) {
                if (isRunning.get()) {
                    logger.severe("Error accepting connection: " + e.getMessage());
                }
            }
        }
    }

    public void stop() {
        logger.info("Stopping server...");
        isRunning.set(false);

        // Close server socket
        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                logger.warning("Error closing server socket: " + e.getMessage());
            }
        }

        // Shutdown executor service
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }

        logger.info("Server stopped");
    }

    private class ClientHandler implements Runnable {
        private final SSLSocket clientSocket;
        private final String clientInfo;
        private DataInputStream in;
        private DataOutputStream out;

        public ClientHandler(SSLSocket clientSocket, String clientInfo) {
            this.clientSocket = clientSocket;
            this.clientInfo = clientInfo;
        }

        @Override
        public void run() {
            try {
                // Create streams
                in = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
                out = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));

                // Handle client requests
                handleClientRequests();

            } catch (Exception e) {
                logger.severe("Error handling client " + clientInfo + ": " + e.getMessage());
            } finally {
                closeConnection();
            }
        }

        private void handleClientRequests() throws IOException {
            while (!clientSocket.isClosed()) {
                try {
                    String request = in.readUTF();
                    logger.info("Request from " + clientInfo + ": " + request);

                    switch (request.toUpperCase()) {
                        case "UPLOAD":
                            handleUpload();
                            break;
                        case "DOWNLOAD":
                            handleDownload();
                            break;
                        case "DELETE":
                        case "REVOKE":
                            handleDelete();
                            break;
                        case "END":
                            logger.info("Operation ended for " + clientInfo);
                            break;
                        case "QUIT":
                            logger.info("Client " + clientInfo + " disconnecting");
                            return;
                        default:
                            logger.warning("Invalid request from " + clientInfo + ": " + request);
                            sendError("INVALID_REQUEST");
                            break;
                    }
                } catch (EOFException e) {
                    // Client disconnected
                    break;
                } catch (SocketTimeoutException e) {
                    logger.warning("Client " + clientInfo + " timed out");
                    break;
                } catch (Exception e) {
                    logger.severe("Error processing request from " + clientInfo + ": " + e.getMessage());
                    sendError("PROCESSING_ERROR");
                }
            }
        }

        private void handleUpload() throws IOException {
            String filename = in.readUTF();
            int fileLength = in.readInt();

            if (fileLength <= 0 || fileLength > 100 * 1024 * 1024) { // Max 100MB
                logger.warning("Invalid file length from " + clientInfo + ": " + fileLength);
                sendError("INVALID_FILE_LENGTH");
                return;
            }

            // Acquire lock for this file
            Object lock = fileLocks.computeIfAbsent(filename, k -> new Object());

            synchronized (lock) {
                try {
                    byte[] fileBytes = new byte[fileLength];
                    in.readFully(fileBytes);

                    String path = FILES_PATH + sanitizeFilename(filename);
                    writeToFile(path, fileBytes);

                    logger.info("File uploaded by " + clientInfo + ": " + filename);
                    sendSuccess();

                } catch (Exception e) {
                    logger.severe("Error uploading file from " + clientInfo + ": " + e.getMessage());
                    sendError("UPLOAD_FAILED");
                }
            }
        }

        private void handleDownload() throws IOException {
            String filename = in.readUTF();
            int expectedSize = in.readInt(); // -1 means unknown

            String path = FILES_PATH + sanitizeFilename(filename);
            File file = new File(path);

            if (!file.exists()) {
                logger.warning("File not found for " + clientInfo + ": " + filename);
                out.writeInt(0); // File length = 0 indicates not found
                out.flush();
                return;
            }

            // Acquire read lock
            Object lock = fileLocks.computeIfAbsent(filename, k -> new Object());

            synchronized (lock) {
                try {
                    byte[] fileBytes = readFromFile(path);
                    out.writeInt(fileBytes.length);
                    out.write(fileBytes);
                    out.flush();

                    logger.info("File downloaded by " + clientInfo + ": " + filename);

                } catch (Exception e) {
                    logger.severe("Error downloading file for " + clientInfo + ": " + e.getMessage());
                    out.writeInt(0);
                    out.flush();
                }
            }
        }

        private void handleDelete() throws IOException {
            String filename = in.readUTF();
            String path = FILES_PATH + sanitizeFilename(filename);

            // Acquire exclusive lock
            Object lock = fileLocks.computeIfAbsent(filename, k -> new Object());

            synchronized (lock) {
                try {
                    File file = new File(path);
                    if (file.exists()) {
                        // Secure deletion - overwrite with random data before deleting
                        secureDelete(file);
                        logger.info("File deleted by " + clientInfo + ": " + filename);
                        sendSuccess();
                    } else {
                        logger.warning("File not found for deletion by " + clientInfo + ": " + filename);
                        sendError("FILE_NOT_FOUND");
                    }
                } catch (Exception e) {
                    logger.severe("Error deleting file for " + clientInfo + ": " + e.getMessage());
                    sendError("DELETE_FAILED");
                } finally {
                    fileLocks.remove(filename);
                }
            }
        }

        private void sendSuccess() throws IOException {
            out.writeUTF("SUCCESS");
            out.flush();
        }

        private void sendError(String errorCode) throws IOException {
            out.writeUTF("ERROR:" + errorCode);
            out.flush();
        }

        private void closeConnection() {
            try {
                if (in != null)
                    in.close();
                if (out != null)
                    out.close();
                if (clientSocket != null && !clientSocket.isClosed()) {
                    clientSocket.close();
                }
                logger.info("Connection closed for " + clientInfo);
            } catch (IOException e) {
                logger.warning("Error closing connection for " + clientInfo + ": " + e.getMessage());
            }
        }
    }

    private String sanitizeFilename(String filename) {
        // Prevent directory traversal attacks
        return filename.replaceAll("[^a-zA-Z0-9.-]", "_");
    }

    private void writeToFile(String path, byte[] fileBytes) throws IOException {
        Path filePath = Paths.get(path);
        Files.write(filePath, fileBytes);
    }

    private byte[] readFromFile(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }

    private void secureDelete(File file) throws IOException {
        if (!file.exists())
            return;

        long length = file.length();
        SecureRandom random = new SecureRandom();

        try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
            // Overwrite with random data 3 times
            for (int i = 0; i < 3; i++) {
                raf.seek(0);
                byte[] data = new byte[1024];
                long written = 0;
                while (written < length) {
                    random.nextBytes(data);
                    raf.write(data, 0, (int) Math.min(data.length, length - written));
                    written += data.length;
                }
            }
        }

        if (!file.delete()) {
            throw new IOException("Failed to delete file after overwriting");
        }
    }

    public static void main(String[] args) {
        SSLServer server = new SSLServer();

        // Add shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutdown hook triggered");
            server.stop();
        }));

        try {
            server.start();
        } catch (Exception e) {
            logger.severe("Failed to start server: " + e.getMessage());
            System.exit(1);
        }
    }
}