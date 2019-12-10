import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto{
    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        byte[] cipherText;
        // does not actually use ECB acts like NONE but NONE does not work
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(plaintext);

        return cipherText;
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        byte[] plainText;
        // does not actually use ECB acts like NONE but NONE does not work
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        plainText = cipher.doFinal(ciphertext);

        return plainText;
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile) throws IOException, CertificateException
    {
        File certFile = new File(certfile);
        InputStream certInputStream = new FileInputStream(certFile);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certInputStream);
        PublicKey publicKey = certificate.getPublicKey();

        System.out.println("public key");
        System.out.println(publicKey.getEncoded());

        return publicKey;
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException
    {
        File keyFile = new File(keyfile);
        byte[] keyByte = Files.readAllBytes(keyFile.toPath());
        System.out.println("private key");
        System.out.println(new String(keyByte));
        PKCS8EncodedKeySpec keyPKCS8 = new PKCS8EncodedKeySpec(keyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keyPKCS8);

        return privateKey;
    }

    public static KeyPair test() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        return kp;
    }
}
