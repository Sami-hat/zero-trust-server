package encryption;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

@SuppressWarnings("unused")

public class AES {

    private static final byte[] iv = new byte[16];

    public static SecretKey generateAESKey() {
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey aesKey = keyGen.generateKey();
            return aesKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }


    public static byte[] encrypt(byte[] fileBytes, SecretKey secretKey, byte[] iv) throws Exception {
        // Generate IV Spec
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Create key spec
        secretKey = new SecretKeySpec(secretKey.getEncoded(), "AES");

        // Create AES cipher instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Initialize the cipher in encryption mode
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        // Perform encryption
        byte[] encrypted = cipher.doFinal(fileBytes);

        return encrypted;

    }

    public static byte[] decrypt(byte[] encryptedBytes, SecretKey secretKey, byte[] iv) throws Exception {
        // Generate IV Spec
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Create AES cipher instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Initialize the cipher in decryption mode
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        // Perform decryption
        byte[] decrypted = cipher.doFinal(encryptedBytes);

        return decrypted;

    }

}
    
