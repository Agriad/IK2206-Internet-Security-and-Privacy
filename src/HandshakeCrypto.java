import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class HandshakeCrypto{
    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        byte[] cipherText;
        Cipher cipher = Cipher.getInstance("RSA/CBC/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        cipherText = cipher.doFinal(plaintext);

        return cipherText;
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        byte[] plainText;
        Cipher cipher = Cipher.getInstance("RSA/CBC/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        plainText = cipher.doFinal(ciphertext);

        return plainText;
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile) throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException
    {
        File certFile = new File(certfile);
        byte[] certByte = Files.readAllBytes(certFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec certX509Key = new X509EncodedKeySpec(certByte);
        PublicKey publicKey = keyFactory.generatePublic(certX509Key);

        return publicKey;
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException
    {
        File keyFile = new File(keyfile);
        byte[] keyByte = Files.readAllBytes(keyFile.toPath());
        PKCS8EncodedKeySpec keyPKCS8 = new PKCS8EncodedKeySpec(keyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keyPKCS8);

        return privateKey;
    }
}
