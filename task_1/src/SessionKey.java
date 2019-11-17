import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SessionKey {
    SecretKey secretKey;

    SessionKey(Integer keylength) throws java.security.NoSuchAlgorithmException
    {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(keylength);
        secretKey = keygen.generateKey();
    }

    SessionKey(String encodedkey)
    {
        byte[] keyByte = encodedkey.getBytes();
        byte[] key = Base64.getDecoder().decode(keyByte);
        secretKey = new SecretKeySpec(key, 0, key.length, "AES");
    }

    SecretKey getSecretKey()
    {
        SecretKey generatedKey = this.secretKey;
        return generatedKey;
    }

    String encodeKey()
    {
        byte[] key = secretKey.getEncoded();
        String encodedKey = Base64.getEncoder().encodeToString(key);
        return encodedKey;
    }

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
}
