import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionDecrypter {
    private Cipher cipher;

    // constructor that takes key and iv to make a cipher for decoding
    SessionDecrypter(String key, String iv) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException
    {
        Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
        byte[] decodedKey = Base64.getDecoder().decode(key);
        //SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        SessionKey sessionKey = new SessionKey(key);
        SecretKey secretKey = sessionKey.getSecretKey();
        byte[] initializationVector = Base64.getDecoder().decode(iv);
        IvParameterSpec IV = new IvParameterSpec(initializationVector);
        c.init(Cipher.DECRYPT_MODE, secretKey, IV);
        cipher = c;
    }

    // returns an input stream that decodes the stream using the cipher created by the class constructor
    CipherInputStream openCipherInputStream(InputStream input)
    {
        CipherInputStream theCipherInputStream = new CipherInputStream(input, cipher);
        return theCipherInputStream;
    }
}
