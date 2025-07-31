package client;

import java.io.*;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import encryption.*;

public class SSLClient {
    private static final Logger logger = Logger.getLogger(SSLClient.class.getName());

    // Configuration
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 23068;
    private static final int SOCKET_TIMEOUT = 30000; // 30 seconds
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final long RETRY_DELAY_MS = 1000;

    private final ClientFactory clientFactory;
    private SSLSocket clientSocket;
    private DataInputStream in;
    private DataOutputStream out;

    private final String username;
    private final String password;
    private final String filesPath;
    private final String groupsPath;
    private final String privateKeyPath;
    private final String publicKeysPath;

    // File operation queue for batch processing
    private final BlockingQueue<FileOperation> operationQueue;
    private final ExecutorService operationExecutor;

    public SSLClient(String username, String password) throws NoSuchAlgorithmException, KeyManagementException {
        this.username = username;
        this.password = password;
        this.clientFactory = new ClientFactory(username, password);

        this.filesPath = "client_data/" + username + "/";
        this.groupsPath = "server_groups/";
        this.privateKeyPath = "resources/clients/" + username + "/" + username + "-private-key.pem";
        this.publicKeysPath = "resources/pubkeys/";

        this.operationQueue = new LinkedBlockingQueue<>();
        this.operationExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "FileOperationProcessor");
            t.setDaemon(true);
            return t;
        });

        setupLogging();
        ensureDirectoriesExist();
    }

    private void setupLogging() {
        try {
            FileHandler fileHandler = new FileHandler("client_" + username + ".log", true);
            fileHandler.setFormatter(new SimpleFormatter());
            logger.addHandler(fileHandler);
            logger.setLevel(Level.INFO);
        } catch (IOException e) {
            logger.severe("Failed to setup logging: " + e.getMessage());
        }
    }

    private void ensureDirectoriesExist() {
        new File(filesPath).mkdirs();
        new File(groupsPath).mkdirs();
    }

    private void connect() throws IOException, NoSuchAlgorithmException, KeyManagementException {
        if (clientSocket != null && !clientSocket.isClosed()) {
            return; // Already connected
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
                new KeyManager[] { clientFactory.getX509KeyManager() },
                new TrustManager[] { clientFactory.getX509TrustManager() },
                new SecureRandom());

        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        clientSocket = (SSLSocket) socketFactory.createSocket(SERVER_HOST, SERVER_PORT);
        clientSocket.setEnabledProtocols(new String[] { "TLSv1.3" });
        clientSocket.setSoTimeout(SOCKET_TIMEOUT);

        in = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
        out = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));

        logger.info("Connected to server");
    }

    private void disconnect() {
        try {
            if (in != null)
                in.close();
            if (out != null)
                out.close();
            if (clientSocket != null && !clientSocket.isClosed()) {
                clientSocket.close();
            }
            logger.info("Disconnected from server");
        } catch (IOException e) {
            logger.warning("Error during disconnect: " + e.getMessage());
        }
    }

    private void reconnect()
            throws IOException, NoSuchAlgorithmException, KeyManagementException, InterruptedException {
        disconnect();
        Thread.sleep(RETRY_DELAY_MS);
        connect();
    }

    private <T> T executeWithRetry(Operation<T> operation) throws Exception {
        Exception lastException = null;

        for (int attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
            try {
                if (clientSocket == null || clientSocket.isClosed()) {
                    connect();
                }
                return operation.execute();
            } catch (IOException e) {
                lastException = e;
                logger.warning("Operation failed (attempt " + (attempt + 1) + "): " + e.getMessage());

                if (attempt < MAX_RETRY_ATTEMPTS - 1) {
                    try {
                        reconnect();
                    } catch (Exception reconnectEx) {
                        logger.severe("Reconnection failed: " + reconnectEx.getMessage());
                    }
                }
            }
        }

        throw new IOException("Operation failed after " + MAX_RETRY_ATTEMPTS + " attempts", lastException);
    }

    // Enhanced ACL Management with proper file locking
    private void updateACL(String path, String name, String permissions) throws IOException, InterruptedException {
        Path aclPath = Paths.get(path);
        Path tempPath = aclPath.resolveSibling(aclPath.getFileName() + ".tmp");

        // Use file locking for concurrent access
        try (RandomAccessFile raf = new RandomAccessFile(aclPath.toFile(), "rw");
                FileLock lock = raf.getChannel().lock()) {

            List<String> lines = Files.exists(aclPath) ? Files.readAllLines(aclPath) : new ArrayList<>();
            Map<String, Set<String>> aclMap = new HashMap<>();

            // Parse existing ACL
            for (String line : lines) {
                String[] parts = line.split(",", 2);
                if (parts.length >= 1) {
                    String perm = parts[0];
                    Set<String> users = aclMap.computeIfAbsent(perm, k -> new HashSet<>());
                    if (parts.length > 1) {
                        users.addAll(Arrays.asList(parts[1].split(",")));
                    }
                }
            }

            // Update ACL
            aclMap.computeIfAbsent(permissions, k -> new HashSet<>()).add(name);

            // Write updated ACL
            try (BufferedWriter writer = Files.newBufferedWriter(tempPath)) {
                for (Map.Entry<String, Set<String>> entry : aclMap.entrySet()) {
                    writer.write(entry.getKey() + "," + String.join(",", entry.getValue()));
                    writer.newLine();
                }
            }

            // Atomic move
            Files.move(tempPath, aclPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);

        } catch (OverlappingFileLockException e) {
            logger.warning("ACL file is locked, retrying...");
            Thread.sleep(100);
            updateACL(path, name, permissions); // Retry
        }
    }

    private Set<String> readACL(String path) throws IOException {
        Set<String> members = new HashSet<>();
        Path aclPath = Paths.get(path);

        if (!Files.exists(aclPath)) {
            return members;
        }

        List<String> lines = Files.readAllLines(aclPath);
        for (String line : lines) {
            if (!line.startsWith("owner")) {
                String[] parts = line.split(",");
                if (parts.length > 1) {
                    members.addAll(Arrays.asList(Arrays.copyOfRange(parts, 1, parts.length)));
                }
            }
        }

        return members;
    }

    // Enhanced file operations with integrity checking
    private void uploadFile(String filename, String owner, String ownerPassword) throws Exception {
        executeWithRetry(() -> {
            String filePath = filesPath + filename;
            String aclPath = filesPath + filename + ".acl";
            String publicKeyPath = publicKeysPath + owner + "-public-key.pem";

            byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));

            // Calculate file hash for integrity
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] fileHash = digest.digest(fileBytes);

            // Update ACL
            updateACL(aclPath, owner, ownerPassword != null ? "owner" : "shared");

            // Encrypt file
            SecretKey secretKey = AES.generateAESKey();
            byte[] iv = AES.generateIV();
            byte[] encryptedFileBytes = AES.encrypt(fileBytes, secretKey, iv);

            // Encrypt key and IV
            PublicKey publicKey = RSA.loadPublicKey(publicKeyPath);
            byte[] encryptedKey = RSA.encrypt(secretKey.getEncoded(), publicKey);
            byte[] encryptedIV = RSA.encrypt(iv, publicKey);

            // Upload file with hash
            String hashedFilename = hashString(filename, owner, ownerPassword);

            send("UPLOAD");
            send(hashedFilename);
            send(encryptedFileBytes.length);
            out.write(encryptedFileBytes);
            out.flush();

            // Upload key
            send("UPLOAD");
            send(hashString("key-" + filename, owner, ownerPassword));
            send(encryptedKey.length);
            out.write(encryptedKey);
            out.flush();

            // Upload IV
            send("UPLOAD");
            send(hashString("iv-" + filename, owner, ownerPassword));
            send(encryptedIV.length);
            out.write(encryptedIV);
            out.flush();

            // Upload hash for integrity
            send("UPLOAD");
            send(hashString("hash-" + filename, owner, ownerPassword));
            send(fileHash.length);
            out.write(fileHash);
            out.flush();

            send("END");

            logger.info("File uploaded successfully: " + filename);
            return null;
        });
    }

    private void downloadFile(String filename, String owner, String ownerPassword) throws Exception {
        executeWithRetry(() -> {
            String filePath = filesPath + filename;

            // Download encrypted file
            send("DOWNLOAD");
            send(hashString(filename, owner, ownerPassword));
            send(-1);
            byte[] encryptedFileBytes = receive();

            // Download key
            send("DOWNLOAD");
            send(hashString("key-" + filename, owner, ownerPassword));
            send(256);
            byte[] encryptedAESKey = receive();

            // Download IV
            send("DOWNLOAD");
            send(hashString("iv-" + filename, owner, ownerPassword));
            send(256);
            byte[] encryptedIV = receive();

            // Download hash
            send("DOWNLOAD");
            send(hashString("hash-" + filename, owner, ownerPassword));
            send(32); // SHA-256 hash size
            byte[] expectedHash = receive();

            send("END");

            // Decrypt key and IV
            PrivateKey privateKey = RSA.loadPrivateKey(privateKeyPath);
            byte[] aesKey = RSA.decrypt(encryptedAESKey, privateKey);
            byte[] iv = RSA.decrypt(encryptedIV, privateKey);

            // Decrypt file
            SecretKey secretKey = new SecretKeySpec(aesKey, "AES");
            byte[] fileBytes = AES.decrypt(encryptedFileBytes, secretKey, iv);

            // Verify integrity
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] actualHash = digest.digest(fileBytes);

            if (!MessageDigest.isEqual(expectedHash, actualHash)) {
                throw new SecurityException("File integrity check failed");
            }

            // Write file
            Files.write(Paths.get(filePath), fileBytes);
            logger.info("File downloaded successfully: " + filename);

            return null;
        });
    }

    private void shareFile(String filename, String targetUser) throws Exception {
        if (targetUser.equals(username)) {
            throw new IllegalArgumentException("Cannot share file with yourself");
        }

        // Handle group sharing
        if (targetUser.startsWith("group")) {
            String groupPath = groupsPath + targetUser + ".csv";
            Set<String> members = readACL(groupPath);

            // Share with each member in parallel
            List<CompletableFuture<Void>> futures = new ArrayList<>();
            for (String member : members) {
                CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                    try {
                        shareFile(filename, member);
                    } catch (Exception e) {
                        logger.severe("Failed to share with " + member + ": " + e.getMessage());
                        throw new CompletionException(e);
                    }
                });
                futures.add(future);
            }

            // Wait for all shares to complete
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
            return;
        }

        // Share with individual user
        uploadFile(filename, targetUser, null);
        logger.info("File shared with " + targetUser + ": " + filename);
    }

    private void deleteFile(String filename) throws Exception {
        String aclPath = filesPath + filename + ".acl";

        // Read all users who have access
        Set<String> sharedUsers = readACL(aclPath);

        // Revoke from owner
        revokeFile(filename, username, password);

        // Revoke from all shared users
        for (String user : sharedUsers) {
            if (!user.equals(username)) {
                revokeFile(filename, user, null);
            }
        }

        // Delete local ACL file
        Files.deleteIfExists(Paths.get(aclPath));

        // Delete local file
        Files.deleteIfExists(Paths.get(filesPath + filename));

        logger.info("File deleted: " + filename);
    }

    private void revokeFile(String filename, String user, String userPassword) throws Exception {
        executeWithRetry(() -> {
            // Handle group revocation
            if (user.startsWith("group")) {
                String groupPath = groupsPath + user + ".csv";
                Set<String> members = readACL(groupPath);
                for (String member : members) {
                    revokeFile(filename, member, null);
                }
                return null;
            }

            // Revoke individual user access
            send("DELETE");
            send(hashString(filename, user, userPassword));

            send("DELETE");
            send(hashString("key-" + filename, user, userPassword));

            send("DELETE");
            send(hashString("iv-" + filename, user, userPassword));

            send("DELETE");
            send(hashString("hash-" + filename, user, userPassword));

            send("END");

            logger.info("Revoked access for " + user + " to file: " + filename);
            return null;
        });
    }

    // Helper methods
    private void send(String data) throws IOException {
        out.writeUTF(data);
        out.flush();
    }

    private void send(int data) throws IOException {
        out.writeInt(data);
        out.flush();
    }

    private byte[] receive() throws IOException {
        int length = in.readInt();
        if (length == 0) {
            throw new FileNotFoundException("File not found on server");
        }

        byte[] data = new byte[length];
        in.readFully(data);
        return data;
    }

    private String hashString(String filename, String name, String password) {
        try {
            String combined = name + (password != null ? password : "") + filename;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(combined.getBytes("UTF-8"));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            logger.severe("Failed to hash string: " + e.getMessage());
            throw new RuntimeException("Hashing failed", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // File operation queue for batch processing
    private static class FileOperation {
        enum Type {
            UPLOAD, DOWNLOAD, SHARE, DELETE, REVOKE
        }

        final Type type;
        final String filename;
        final String targetUser;
        final String password;
        final CompletableFuture<Void> future;

        FileOperation(Type type, String filename, String targetUser, String password) {
            this.type = type;
            this.filename = filename;
            this.targetUser = targetUser;
            this.password = password;
            this.future = new CompletableFuture<>();
        }
    }

    // Batch operation processing
    public CompletableFuture<Void> submitOperation(FileOperation.Type type, String filename,
            String targetUser, String password) {
        FileOperation op = new FileOperation(type, filename, targetUser, password);
        operationQueue.offer(op);
        return op.future;
    }

    private void processOperations() {
        operationExecutor.submit(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    FileOperation op = operationQueue.take();

                    try {
                        switch (op.type) {
                            case UPLOAD:
                                uploadFile(op.filename, op.targetUser != null ? op.targetUser : username, op.password);
                                break;
                            case DOWNLOAD:
                                downloadFile(op.filename, op.targetUser != null ? op.targetUser : username,
                                        op.password);
                                break;
                            case SHARE:
                                shareFile(op.filename, op.targetUser);
                                break;
                            case DELETE:
                                deleteFile(op.filename);
                                break;
                            case REVOKE:
                                revokeFile(op.filename, op.targetUser, null);
                                break;
                        }
                        op.future.complete(null);
                    } catch (Exception e) {
                        op.future.completeExceptionally(e);
                    }

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
    }

    // Interactive CLI
    public void startInteractiveMode() throws Exception {
        connect();
        processOperations(); // Start background processor

        Scanner scanner = new Scanner(System.in);

        while (true) {
            try {
                System.out.println("\n===== SSL File Server Client =====");
                System.out.println("1. Upload file");
                System.out.println("2. Download file");
                System.out.println("3. Share file");
                System.out.println("4. Delete file");
                System.out.println("5. Revoke access");
                System.out.println("6. Batch upload");
                System.out.println("7. List local files");
                System.out.println("8. Quit");
                System.out.print("Select option: ");

                int choice = scanner.nextInt();
                scanner.nextLine(); // Consume newline

                switch (choice) {
                    case 1:
                        handleUploadCommand(scanner);
                        break;
                    case 2:
                        handleDownloadCommand(scanner);
                        break;
                    case 3:
                        handleShareCommand(scanner);
                        break;
                    case 4:
                        handleDeleteCommand(scanner);
                        break;
                    case 5:
                        handleRevokeCommand(scanner);
                        break;
                    case 6:
                        handleBatchUpload(scanner);
                        break;
                    case 7:
                        listLocalFiles();
                        break;
                    case 8:
                        quit();
                        return;
                    default:
                        System.out.println("Invalid option");
                }
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                logger.severe("Command failed: " + e.getMessage());
            }
        }
    }

    private void handleUploadCommand(Scanner scanner) throws Exception {
        System.out.print("Enter filename: ");
        String filename = scanner.nextLine().trim();

        if (!new File(filesPath + filename).exists()) {
            System.out.println("File not found locally: " + filename);
            return;
        }

        uploadFile(filename, username, password);
        System.out.println("File uploaded successfully");
    }

    private void handleDownloadCommand(Scanner scanner) throws Exception {
        System.out.print("Enter filename: ");
        String filename = scanner.nextLine().trim();

        System.out.print("Enter owner username (or press Enter for self): ");
        String owner = scanner.nextLine().trim();
        if (owner.isEmpty())
            owner = username;

        String ownerPassword = null;
        if (owner.equals(username)) {
            ownerPassword = password;
        }

        downloadFile(filename, owner, ownerPassword);
        System.out.println("File downloaded successfully");
    }

    private void handleShareCommand(Scanner scanner) throws Exception {
        System.out.print("Enter filename: ");
        String filename = scanner.nextLine().trim();

        System.out.print("Enter username/group to share with: ");
        String target = scanner.nextLine().trim();

        shareFile(filename, target);
        System.out.println("File shared successfully");
    }

    private void handleDeleteCommand(Scanner scanner) throws Exception {
        System.out.print("Enter filename: ");
        String filename = scanner.nextLine().trim();

        System.out.print("Are you sure you want to delete " + filename + "? (y/n): ");
        String confirm = scanner.nextLine().trim();

        if (confirm.equalsIgnoreCase("y")) {
            deleteFile(filename);
            System.out.println("File deleted successfully");
        } else {
            System.out.println("Delete cancelled");
        }
    }

    private void handleRevokeCommand(Scanner scanner) throws Exception {
        System.out.print("Enter filename: ");
        String filename = scanner.nextLine().trim();

        System.out.print("Enter username/group to revoke access from: ");
        String target = scanner.nextLine().trim();

        revokeFile(filename, target, null);
        System.out.println("Access revoked successfully");
    }

    private void handleBatchUpload(Scanner scanner) throws Exception {
        System.out.print("Enter directory path: ");
        String dirPath = scanner.nextLine().trim();

        File dir = new File(dirPath);
        if (!dir.exists() || !dir.isDirectory()) {
            System.out.println("Invalid directory path");
            return;
        }

        File[] files = dir.listFiles(File::isFile);
        if (files == null || files.length == 0) {
            System.out.println("No files found in directory");
            return;
        }

        System.out.println("Found " + files.length + " files. Starting batch upload...");

        List<CompletableFuture<Void>> futures = new ArrayList<>();
        for (File file : files) {
            // Copy file to client directory
            Path source = file.toPath();
            Path target = Paths.get(filesPath + file.getName());
            Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);

            // Submit upload operation
            CompletableFuture<Void> future = submitOperation(
                    FileOperation.Type.UPLOAD, file.getName(), username, password);
            futures.add(future);
        }

        // Wait for all uploads to complete
        CompletableFuture<Void> allUploads = CompletableFuture.allOf(
                futures.toArray(new CompletableFuture[0]));

        allUploads.thenRun(() -> {
            System.out.println("Batch upload completed successfully");
        }).exceptionally(e -> {
            System.err.println("Batch upload failed: " + e.getMessage());
            return null;
        });
    }

    private void listLocalFiles() {
        File dir = new File(filesPath);
        File[] files = dir.listFiles(f -> f.isFile() && !f.getName().endsWith(".acl"));

        if (files == null || files.length == 0) {
            System.out.println("No files found");
            return;
        }

        System.out.println("\nLocal files:");
        System.out.println("----------------------------------------");
        for (File file : files) {
            System.out.printf("%-30s %10d bytes\n", file.getName(), file.length());
        }
        System.out.println("----------------------------------------");
        System.out.println("Total: " + files.length + " files");
    }

    private void quit() throws Exception {
        logger.info("Shutting down client");

        // Stop operation processor
        operationExecutor.shutdown();
        try {
            if (!operationExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                operationExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            operationExecutor.shutdownNow();
        }

        // Send quit command
        try {
            send("QUIT");
        } catch (Exception e) {
            logger.warning("Failed to send QUIT command: " + e.getMessage());
        }

        disconnect();
        System.out.println("Goodbye!");
    }

    // Functional interface for retryable operations
    @FunctionalInterface
    private interface Operation<T> {
        T execute() throws Exception;
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java SSLClient <username> <password>");
            System.exit(1);
        }

        String username = args[0];
        String password = args[1];

        try {
            SSLClient client = new SSLClient(username, password);
            client.startInteractiveMode();
        } catch (Exception e) {
            System.err.println("Fatal error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}