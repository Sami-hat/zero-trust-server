package encryption;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSA {

    public static byte[] encrypt(byte[] plainData, PublicKey publicKey) throws BadPaddingException, IllegalBlockSizeException, 
    InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        // Initialize the Cipher for encryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Perform encryption
        return cipher.doFinal(plainData);
    }


    public static byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws BadPaddingException, IllegalBlockSizeException, 
    InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {

        // Initialize the Cipher for decryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // Decrypt the data
        return cipher.doFinal(encryptedData);
    }


    public static RSAPublicKey loadPublicKey(String keyPath) throws Exception {
        String publicKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(keyPath).toURI())));

        publicKeyContent = publicKeyContent
            .replaceAll(System.lineSeparator(), "")
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "");

        KeyFactory kf = KeyFactory.getInstance("RSA");

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

        return pubKey;
    }


    public static PrivateKey loadPrivateKey(String keyPath) throws Exception {        
        String privateKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(keyPath).toURI())));
        
        privateKeyContent = privateKeyContent
            .replaceAll(System.lineSeparator(), "")
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "");

        KeyFactory kf = KeyFactory.getInstance("RSA");
        
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

        return privKey;
    }
}