package client;

import java.security.KeyStore;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;

// import java.security.KeyManagementException;
// import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import encryption.*;

@SuppressWarnings("unused")

public class ClientFactory {

    private String username;
    private String password;

    private String KEYSTORE_PATH;
    private String TRUSTSTORE_PATH;

    private static final String SCRIPT_PATH = "scripts/run_client.sh";

    private KeyManagerFactory keyManagerFactory;
    private TrustManagerFactory trustManagerFactory;

    private X509TrustManager x509TrustManager;
    private X509KeyManager x509KeyManager;

    public ClientFactory(String username, String password) {
        try {

            this.username = username;
            this.password = password;

            // Generate eystore and truststore for client
            ProcessBuilder processBuilder = new ProcessBuilder("bash", SCRIPT_PATH, username, password);
            Process process = processBuilder.start();
            // process.getInputStream().toString();
            process.waitFor();

            this.KEYSTORE_PATH = "resources/clients/" + username + "/" + username + "-keystore.p12";
            this.TRUSTSTORE_PATH = "resources/clients/" + username + "/" + username + "-truststore.p12";

            // KeyStore
            KeyStore keystore = KeyStore.getInstance("PKCS12");

            InputStream clientInputStream = ClassLoader.getSystemClassLoader().getResourceAsStream(this.KEYSTORE_PATH);
            keystore.load(clientInputStream, password.toCharArray());

            // TrustManagerFactory
            KeyStore trustStore = KeyStore.getInstance("PKCS12");

            trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
            InputStream serverInputStream = ClassLoader.getSystemClassLoader()
                    .getResourceAsStream(this.TRUSTSTORE_PATH);
            trustStore.load(serverInputStream, password.toCharArray());
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
            keyManagerFactory.init(keystore, password.toCharArray());

            x509KeyManager = null;
            for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
                if (keyManager instanceof X509KeyManager) {
                    x509KeyManager = (X509KeyManager) keyManager;
                    break;
                }
            }

            if (x509KeyManager == null)
                throw new NullPointerException();

        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
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

    public byte[] getPublicKey() {
        return null;
    }

    public static void main(String[] args) {
        String username = "client1";
        String password = "123456";
        new ClientFactory(username, password);
    }
}
