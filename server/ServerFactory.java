package server;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

@SuppressWarnings("unused")

public class ServerFactory {

    private static final String KEYSTORE_PATH = "resources/server/server-keystore.p12";
    private static final String TRUSTSTORE_PATH = "resources/server/server-truststore.p12";

    private static final String PASSWORD = "123456";

    private static final String SCRIPT_PATH = "scripts/run_server.sh";

    private KeyManagerFactory keyManagerFactory;
    private TrustManagerFactory trustManagerFactory;

    private X509TrustManager x509TrustManager;
    private X509KeyManager x509KeyManager;

    public ServerFactory() {

        try {
            // Generate RSA keys for client
            ProcessBuilder processBuilder = new ProcessBuilder("bash", SCRIPT_PATH);
            Process process = processBuilder.start();
            process.waitFor();

            // Get the keystore
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            try (InputStream serverInputStream = new FileInputStream(KEYSTORE_PATH)) {
                keystore.load(serverInputStream, PASSWORD.toCharArray());
            } catch (FileNotFoundException e) {
                System.out.println("keystore file not foud");
            } catch (IOException e) {
                System.out.println("IO error");
                e.printStackTrace();
            }

            // TrustManagerFactory
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
            try (InputStream clientInputStream = new FileInputStream(TRUSTSTORE_PATH)) {
                trustStore.load(clientInputStream, PASSWORD.toCharArray());
            } catch (FileNotFoundException e) {
                System.out.println("trustore file not foud");
            } catch (IOException e) {
                System.out.println("IO error");
                e.printStackTrace();
            }

            trustManagerFactory.init(trustStore);
            x509TrustManager = null;
            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager) {
                    x509TrustManager = (X509TrustManager) trustManager;
                    break;
                }
            }

            // KeyManagerFactory
            keyManagerFactory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
            keyManagerFactory.init(keystore, PASSWORD.toCharArray());
            x509KeyManager = null;
            for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
                if (keyManager instanceof X509KeyManager) {
                    x509KeyManager = (X509KeyManager) keyManager;
                    break;
                }
            }
            if (x509KeyManager == null)
                throw new NullPointerException("No X509KeyManager found");

        } catch (CertificateException e) {
            System.err.println("Certificate error: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm error: " + e.getMessage());
        } catch (UnrecoverableKeyException e) {
            System.err.println("Unrecoverable key error: " + e.getMessage());
        } catch (NoSuchProviderException e) {
            System.err.println("Provider error: " + e.getMessage());
        } catch (KeyStoreException e) {
            System.err.println("Keystore error: " + e.getMessage());
        } catch (IOException e) {
            System.out.println("IO error" + e.getMessage());
        } catch (InterruptedException e) {
            System.out.println("Interrupted error" + e.getMessage());
        }
    }

    public KeyManagerFactory getKeyManagerFactory() {
        return keyManagerFactory;
    }

    public TrustManagerFactory getTrustManagerFactory() {
        return trustManagerFactory;
    }

    public X509TrustManager getX509TrustManager() {
        return x509TrustManager;
    }

    public X509KeyManager getX509KeyManager() {
        return x509KeyManager;
    }

    public static void main(String[] args) {
        ServerFactory serverFactory = new ServerFactory();
        // System.out.println("ServerFactory created");
    }
}