import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SessionKey {
    private SecretKey secretKey;

    // Makes an AES key with length keyLength
    SessionKey(Integer keylength) throws java.security.NoSuchAlgorithmException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keylength);
        secretKey = keyGen.generateKey();
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

/*
Key quality means a number of things and in the case with AES, which we are using, one of them is key length.
The longer the key the more secure it is but AES can only use length 128, 192, and 256. This is because it adds more
rounds and more complexity which is better at resisting cryptanalysis attacks. Another one would be the randomness of
the key being generated as a predictable one would cause certain keys to have a higher change of being generated.

A way a program can check for key quality is to check if the key is as long or longer than the current recommended
length. Another thing that it can do is to produce multiple keys and check if any are the same. This would show if the
key generator has a bias and therefore a weakness. Another thing it could check would be for patterns that occur in
the key, like where parts of the key have a tendency to show up more often or how it could reveal the seed that
generated the key.
*/


