import java.security.*;
public class HandshakeTester {
    /*
    static String PRIVATEKEYFILE =
            "/Users/Justin/Desktop/Games/Programming/Github/" +
                    "IK2206-internet-security-and-privacy/src/ca-private-pkcs8.der";
    static String CERTFILE =
            "/Users/Justin/Desktop/Games/Programming/Github/IK2206-internet-security-and-privacy/src/CA.pem";

     */

    /*
    static String PRIVATEKEYFILE =
            "/Users/Justin/Desktop/Games/Programming/Github/" +
                    "IK2206-internet-security-and-privacy/src/ca-private-key.der";
    static String CERTFILE =
            "/Users/Justin/Desktop/Games/Programming/Github/IK2206-internet-security-and-privacy/src/ca.pem";

     */

    static String PRIVATEKEYFILE =
            "/Users/Justin/Desktop/Games/Programming/Github/" +
                    "IK2206-internet-security-and-privacy/src/client-private.der";
    static String CERTFILE =
            "/Users/Justin/Desktop/Games/Programming/Github/IK2206-internet-security-and-privacy/src/client.pem";


    static String PLAINTEXT = "Time flies like an arrow. Fruit flies like a banana.";
    //static String PLAINTEXT = "Time";
    static String ENCODING = "UTF-8"; /* For converting between strings and byte arrays */
    static public void main(String[] args) throws Exception {
        /* Extract key pair */

        PublicKey publickey = HandshakeCrypto.getPublicKeyFromCertFile(CERTFILE);
        PrivateKey privatekey =
                HandshakeCrypto.getPrivateKeyFromKeyFile(PRIVATEKEYFILE);

        /*
        KeyPair kp = HandshakeCrypto.test();
        PublicKey publickey = kp.getPublic();
        PrivateKey privatekey = kp.getPrivate();
         */

        /* Encode string as bytes */
        byte[] plaininputbytes = PLAINTEXT.getBytes(ENCODING);
        System.out.println("string plain");
        System.out.println(new String(plaininputbytes));
        /* Encrypt it */
        byte[] cipher = HandshakeCrypto.encrypt(plaininputbytes, publickey);
        System.out.println("string encrypted");
        System.out.println(new String(cipher));
        /* Then decrypt back */
        byte[] plainoutputbytes = HandshakeCrypto.decrypt(cipher, privatekey);
        System.out.println("string decrypted");
        System.out.println(new String(plainoutputbytes));
        /* Decode bytes into string */
        String plainoutput = new String(plainoutputbytes, ENCODING);
        if (plainoutput.equals(PLAINTEXT)) {
            System.out.println("Pass. Input and output strings are the same: \"" +
                    PLAINTEXT + "\"");
        }
        else {
            System.out.println("Fail. Expected \"" + PLAINTEXT + "\", but got \"" +
                    plainoutput + "\'");
            System.out.println("FAIL");
        }
    }
}