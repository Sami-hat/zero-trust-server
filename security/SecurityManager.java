package security;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SecurityManager {
    private static final Logger logger = Logger.getLogger(SecurityManager.class.getName());

    // Security constants
    private static final int SALT_LENGTH = 32;
    private static final int PBKDF2_ITERATIONS = 100000;
    private static final int KEY_LENGTH = 256;
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";

    // Session management
    private final Map<String, SessionInfo> activeSessions;
    private final SecureRandom secureRandom;

    public SecurityManager() {
        this.activeSessions = new ConcurrentHashMap<>();
        this.secureRandom = new SecureRandom();
    }

    // Session management
    public static class SessionInfo {
        private final String sessionId;
        private final String username;
        private final long creationTime;
        private final long expirationTime;
        private final byte[] sessionKey;
        private long lastAccessTime;

        public SessionInfo(String sessionId, String username, long ttlMillis, byte[] sessionKey) {
            this.sessionId = sessionId;
            this.username = username;
            this.creationTime = System.currentTimeMillis();
            this.expirationTime = creationTime + ttlMillis;
            this.sessionKey = sessionKey;
            this.lastAccessTime = creationTime;
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > expirationTime;
        }

        public void updateLastAccess() {
            this.lastAccessTime = System.currentTimeMillis();
        }

        // Getters
        public String getSessionId() {
            return sessionId;
        }

        public String getUsername() {
            return username;
        }

        public byte[] getSessionKey() {
            return sessionKey.clone();
        }
    }

    // Create new session
    public SessionInfo createSession(String username, long ttlMillis) {
        String sessionId = generateSessionId();
        byte[] sessionKey = generateRandomBytes(32);

        SessionInfo session = new SessionInfo(sessionId, username, ttlMillis, sessionKey);
        activeSessions.put(sessionId, session);

        logger.info("Created session for user: " + username);
        return session;
    }

    // Validate session
    public SessionInfo validateSession(String sessionId) {
        SessionInfo session = activeSessions.get(sessionId);

        if (session == null) {
            return null;
        }

        if (session.isExpired()) {
            activeSessions.remove(sessionId);
            logger.warning("Session expired for user: " + session.getUsername());
            return null;
        }

        session.updateLastAccess();
        return session;
    }

    // End session
    public void endSession(String sessionId) {
        SessionInfo session = activeSessions.remove(sessionId);
        if (session != null) {
            logger.info("Ended session for user: " + session.getUsername());
        }
    }

    // Clean up expired sessions
    public void cleanupExpiredSessions() {
        activeSessions.entrySet().removeIf(entry -> {
            if (entry.getValue().isExpired()) {
                logger.info("Cleaning up expired session for user: " + entry.getValue().getUsername());
                return true;
            }
            return false;
        });
    }

    // Password hashing with salt
    public String hashPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        byte[] hash = factory.generateSecret(spec).getEncoded();

        // Combine salt and hash
        byte[] combined = new byte[salt.length + hash.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(hash, 0, combined, salt.length, hash.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    // Verify password
    public boolean verifyPassword(String password, String storedHash)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] combined = Base64.getDecoder().decode(storedHash);

        // Extract salt and hash
        byte[] salt = new byte[SALT_LENGTH];
        byte[] hash = new byte[combined.length - SALT_LENGTH];
        System.arraycopy(combined, 0, salt, 0, SALT_LENGTH);
        System.arraycopy(combined, SALT_LENGTH, hash, 0, hash.length);

        // Hash the provided password with the same salt
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        byte[] testHash = factory.generateSecret(spec).getEncoded();

        // Compare hashes
        return MessageDigest.isEqual(hash, testHash);
    }

    // Generate secure random bytes
    public byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    // Generate salt
    public byte[] generateSalt() {
        return generateRandomBytes(SALT_LENGTH);
    }

    // Generate session ID
    private String generateSessionId() {
        byte[] bytes = generateRandomBytes(32);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // File integrity using HMAC
    public byte[] calculateHMAC(byte[] data, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        SecretKeySpec secretKey = new SecretKeySpec(key, HMAC_ALGORITHM);
        mac.init(secretKey);
        return mac.doFinal(data);
    }

    // Verify HMAC
    public boolean verifyHMAC(byte[] data, byte[] key, byte[] expectedHMAC)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] actualHMAC = calculateHMAC(data, key);
        return MessageDigest.isEqual(actualHMAC, expectedHMAC);
    }

    // Secure file deletion with multiple overwrites
    public void secureDelete(File file) throws IOException {
        if (!file.exists())
            return;

        long length = file.length();

        try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
            // Overwrite with random data
            overwriteWithPattern(raf, length, null);

            // Overwrite with zeros
            overwriteWithPattern(raf, length, new byte[] { 0 });

            // Overwrite with ones
            overwriteWithPattern(raf, length, new byte[] { (byte) 0xFF });

            // Final random overwrite
            overwriteWithPattern(raf, length, null);
        }

        // Delete the file
        if (!file.delete()) {
            throw new IOException("Failed to delete file after secure overwrite");
        }

        logger.info("Securely deleted file: " + file.getName());
    }

    private void overwriteWithPattern(RandomAccessFile raf, long length, byte[] pattern) throws IOException {
        raf.seek(0);
        byte[] buffer = new byte[4096];
        long written = 0;

        while (written < length) {
            if (pattern == null) {
                secureRandom.nextBytes(buffer);
            } else {
                Arrays.fill(buffer, pattern[0]);
            }

            int toWrite = (int) Math.min(buffer.length, length - written);
            raf.write(buffer, 0, toWrite);
            written += toWrite;
        }
    }

    // Key derivation from password
    public SecretKey deriveKeyFromPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Encrypt with authenticated encryption (AES-GCM)
    public static class EncryptedData {
        public final byte[] ciphertext;
        public final byte[] iv;
        public final byte[] tag;
        public final byte[] salt;

        public EncryptedData(byte[] ciphertext, byte[] iv, byte[] tag, byte[] salt) {
            this.ciphertext = ciphertext;
            this.iv = iv;
            this.tag = tag;
            this.salt = salt;
        }

        public byte[] serialize() {
            ByteBuffer buffer = ByteBuffer.allocate(
                    4 + ciphertext.length +
                            4 + iv.length +
                            4 + tag.length +
                            4 + salt.length);

            buffer.putInt(ciphertext.length);
            buffer.put(ciphertext);
            buffer.putInt(iv.length);
            buffer.put(iv);
            buffer.putInt(tag.length);
            buffer.put(tag);
            buffer.putInt(salt.length);
            buffer.put(salt);

            return buffer.array();
        }

        public static EncryptedData deserialize(byte[] data) {
            ByteBuffer buffer = ByteBuffer.wrap(data);

            int ciphertextLength = buffer.getInt();
            byte[] ciphertext = new byte[ciphertextLength];
            buffer.get(ciphertext);

            int ivLength = buffer.getInt();
            byte[] iv = new byte[ivLength];
            buffer.get(iv);

            int tagLength = buffer.getInt();
            byte[] tag = new byte[tagLength];
            buffer.get(tag);

            int saltLength = buffer.getInt();
            byte[] salt = new byte[saltLength];
            buffer.get(salt);

            return new EncryptedData(ciphertext, iv, tag, salt);
        }
    }

    // Authenticated encryption using AES-GCM
    public EncryptedData encryptAuthenticated(byte[] plaintext, SecretKey key, byte[] associatedData)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = generateRandomBytes(12); // 96-bit IV for GCM
        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128-bit auth tag

        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        if (associatedData != null) {
            cipher.updateAAD(associatedData);
        }

        byte[] ciphertext = cipher.doFinal(plaintext);

        // Extract auth tag (last 16 bytes)
        byte[] tag = new byte[16];
        byte[] actualCiphertext = new byte[ciphertext.length - 16];
        System.arraycopy(ciphertext, 0, actualCiphertext, 0, actualCiphertext.length);
        System.arraycopy(ciphertext, actualCiphertext.length, tag, 0, 16);

        return new EncryptedData(actualCiphertext, iv, tag, new byte[0]);
    }

    // Authenticated decryption
    public byte[] decryptAuthenticated(EncryptedData encData, SecretKey key, byte[] associatedData)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, encData.iv);

        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        if (associatedData != null) {
            cipher.updateAAD(associatedData);
        }

        // Combine ciphertext and tag for decryption
        byte[] combined = new byte[encData.ciphertext.length + encData.tag.length];
        System.arraycopy(encData.ciphertext, 0, combined, 0, encData.ciphertext.length);
        System.arraycopy(encData.tag, 0, combined, encData.ciphertext.length, encData.tag.length);

        return cipher.doFinal(combined);
    }

    // Rate limiting
    private final Map<String, RateLimiter> rateLimiters = new ConcurrentHashMap<>();

    public static class RateLimiter {
        private final int maxRequests;
        private final long windowMillis;
        private final Queue<Long> timestamps;

        public RateLimiter(int maxRequests, long windowMillis) {
            this.maxRequests = maxRequests;
            this.windowMillis = windowMillis;
            this.timestamps = new LinkedList<>();
        }

        public synchronized boolean allowRequest() {
            long now = System.currentTimeMillis();

            // Remove old timestamps
            while (!timestamps.isEmpty() && timestamps.peek() < now - windowMillis) {
                timestamps.poll();
            }

            if (timestamps.size() < maxRequests) {
                timestamps.offer(now);
                return true;
            }

            return false;
        }
    }

    public boolean checkRateLimit(String identifier, int maxRequests, long windowMillis) {
        RateLimiter limiter = rateLimiters.computeIfAbsent(
                identifier, k -> new RateLimiter(maxRequests, windowMillis));
        return limiter.allowRequest();
    }
}