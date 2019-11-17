import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SessionKey {
    SecretKey secretKey;

    // Makes an AES key with length keyLength
    SessionKey(Integer keylength) throws java.security.NoSuchAlgorithmException
    {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(keylength);
        secretKey = keygen.generateKey();
    }

    // Makes a key from a base64 encoded key
    SessionKey(String encodedkey)
    {
        byte[] keyByte = encodedkey.getBytes();
        byte[] key = Base64.getDecoder().decode(keyByte);
        secretKey = new SecretKeySpec(key, 0, key.length, "AES");
    }

    // Returns a key
    SecretKey getSecretKey()
    {
        SecretKey generatedKey = this.secretKey;
        return generatedKey;
    }

    // Returns a key encoded in base64
    String encodeKey()
    {
        byte[] key = secretKey.getEncoded();
        String encodedKey = Base64.getEncoder().encodeToString(key);
        return encodedKey;
    }

    /*
    // Testing
    public static void main(String args[]) throws java.security.NoSuchAlgorithmException
    {
        SessionKey key1 = new SessionKey(128);
        SessionKey key2 = new SessionKey(key1.encodeKey());
        if (key1.getSecretKey().equals(key2.getSecretKey())) {
            System.out.println("Pass");
        }
        else {
            System.out.println("Fail");
        }
    }

    */
}
