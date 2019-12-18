import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class VerifyCertificate {
    public static void main(String[] args) throws
            java.security.cert.CertificateException, java.io.IOException
    {
        File caFile = new File(args[0]);
        File userFile = new File(args[1]);

        InputStream caInStream = new FileInputStream(caFile);
        InputStream userInStream = new FileInputStream(userFile);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(caInStream);
        X509Certificate userCert = (X509Certificate) cf.generateCertificate(userInStream);

        X500Principal caPrincipal = caCert.getIssuerX500Principal();
        X500Principal userPrincipal = userCert.getIssuerX500Principal();

        System.out.println(caPrincipal.getName());
        System.out.println(userPrincipal.getName());

        PublicKey caPublicKey = caCert.getPublicKey();
        PublicKey userPublicKey = userCert.getPublicKey();

        try{
            caCert.verify(caPublicKey);
            userCert.verify(caPublicKey);
            // This is wrong
            //userCert.verify(userPublicKey);
            caCert.checkValidity();
            userCert.checkValidity();

            System.out.println("Pass");
        }
        catch (Exception e)
        {
            System.out.println("Fail");
            System.out.println(e);
            //e.printStackTrace();
            throw new CertificateException("The certificate is not valid");
        }

    }

}
