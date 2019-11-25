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

    // constructor for creating a secretKey, initializationVector, and cipher for encoding
    SessionEncrypter(Integer keylength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException
    {
        Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        //keyGen.init(keylength);
        //secretKey = keyGen.generateKey();
        sessionKey = new SessionKey(keylength);
        secretKey = sessionKey.getSecretKey();
        initializationVector = new byte[keylength / 8];
        secureRandom.nextBytes(initializationVector);
        IvParameterSpec IV = new IvParameterSpec(initializationVector);
        c.init(Cipher.ENCRYPT_MODE, secretKey, IV);
        cipher = c;
    }

    // return base64 encoded key
    String encodeKey()
    {
        //byte[] key = secretKey.getEncoded();
        //String encodedKey = Base64.getEncoder().encodeToString(key);
        String encodedKey = sessionKey.encodeKey();
        return encodedKey;
    }

    // returns base64 encoded initialization vector
    String encodeIV()
    {
        String encodedIV = Base64.getEncoder().encodeToString(initializationVector);
        return encodedIV;
    }

    // returns an output stream that encodes the stream using the cipher created by the class constructor
    CipherOutputStream openCipherOutputStream(OutputStream output)
    {
        CipherOutputStream theCipherOuputStream = new CipherOutputStream(output, cipher);
        return theCipherOuputStream;
    }
}
