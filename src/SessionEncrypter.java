import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionEncrypter {
    private SecretKey secretKey;
    private byte[] initializationVector;
    private Cipher cipher;
    private SessionKey sessionKey;

    // Constructor for creating a secretKey, initializationVector, and cipher for encoding
    SessionEncrypter(Integer keylength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException
    {
        Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        //keyGen.init(keylength);
        //secretKey = keyGen.generateKey();
        this.sessionKey = new SessionKey(keylength);
        this.secretKey = sessionKey.getSecretKey();
        this.initializationVector = new byte[keylength / 8];
        secureRandom.nextBytes(initializationVector);
        IvParameterSpec IV = new IvParameterSpec(initializationVector);
        c.init(Cipher.ENCRYPT_MODE, secretKey, IV);
        this.cipher = c;
    }

    // Constructor using key encoded in base64 and iv encoded in base64
    SessionEncrypter(byte[] key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException
    {
        Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
        this.sessionKey = new SessionKey(new String(key));
        this.secretKey = sessionKey.getSecretKey();
        byte[] initializationVector = Base64.getDecoder().decode(iv);
        this.initializationVector = initializationVector;
        IvParameterSpec IV = new IvParameterSpec(initializationVector);
        c.init(Cipher.ENCRYPT_MODE, secretKey, IV);
        this.cipher = c;
    }

    // Return base64 encoded key
    String encodeKey()
    {
        //byte[] key = secretKey.getEncoded();
        //String encodedKey = Base64.getEncoder().encodeToString(key);
        String encodedKey = sessionKey.encodeKey();
        return encodedKey;
    }

    // Returns base64 encoded initialization vector
    String encodeIV()
    {
        String encodedIV = Base64.getEncoder().encodeToString(initializationVector);
        return encodedIV;
    }

    // Returns byte array session key
    byte[] getKeyBytes()
    {
        return this.secretKey.getEncoded();
    }

    // Returns byte array initialization vector
    byte[] getIVBytes()
    {
        return this.initializationVector;
    }

    // Returns an output stream that encodes the stream using the cipher created by the class constructor
    CipherOutputStream openCipherOutputStream(OutputStream output)
    {
        CipherOutputStream theCipherOuputStream = new CipherOutputStream(output, cipher);
        return theCipherOuputStream;
    }
}
