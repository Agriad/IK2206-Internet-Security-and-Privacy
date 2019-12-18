/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
 
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.lang.AssertionError;
import java.lang.Integer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    //public static final String DEFAULTSERVERHOST = "portfw.kth.se";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;
    
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;

    private String clientCertificatePath = "./current-connection-client.pem";
    private byte[] sessionKey;
    private byte[] sessionIV;

    // validate the client certificate
    private void clientCheck(HandshakeMessage clientHello, Socket socket) throws IOException {
        clientHello.recv(socket);
        String messageType = clientHello.getParameter("MessageType");
        String certificate = clientHello.getParameter("Certificate");

        if (!messageType.equals("ClientHello"))
        {
            throw new IllegalArgumentException("Received: " + messageType + " required: ClientHello");
        }

        byte[] clientCertificateByte = Base64.getDecoder().decode(certificate);
        String clientCertificatePath = this.clientCertificatePath;
        File clientCertificateFile = new File(clientCertificatePath);
        FileOutputStream clientFileOutputStream = new FileOutputStream(clientCertificateFile);
        clientFileOutputStream.write(clientCertificateByte);
        clientFileOutputStream.flush();
        clientFileOutputStream.close();

        String caCertificatePath = "./" + arguments.get("cacert");
        File caCertificateFile = new File(caCertificatePath);

        String[] verifyCertificateInput = {caCertificatePath, clientCertificatePath};

        try {
            VerifyCertificate.main(verifyCertificateInput);
        }
        catch (CertificateException certificateException)
        {
            System.out.println(certificateException.getMessage());

        }
    }

    private void serverHello(HandshakeMessage serverHello, Socket socket) throws IOException {
        serverHello.putParameter("MessageType", "ServerHello");
        String userCertificatePath = "./" + arguments.get("usercert");

        File userCertificateFile = new File(userCertificatePath);
        InputStream userCertificateInputStream = new FileInputStream(userCertificateFile);
        // String userCertificateString = new String(userCertificateInputStream.readAllBytes());
        byte[] userCertificateByte = Base64.getEncoder().encode(userCertificateInputStream.readAllBytes());
        String userCertificateString = new String(userCertificateByte);

        serverHello.putParameter("Certificate", userCertificateString);
        serverHello.send(socket);
    }

    // Takes the clients connection settings and sets them up
    private void forwardMessage(HandshakeMessage forward, Socket socket) throws IOException {
        forward.recv(socket);

        String messageType = forward.getParameter("MessageType");

        if (!messageType.equals("Forward"))
        {
            throw new IllegalArgumentException("Received: " + messageType + " required: ServerHello");
        }

        String portNumberString = forward.getParameter("TargetPort");
        int portNumberInt = Integer.parseInt(portNumberString);

        targetHost = forward.getParameter("TargetHost");
        targetPort = portNumberInt;
    }

    private void sessionMessage(HandshakeMessage session, Socket socket, int sessionPort) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException,
            IOException, CertificateException, BadPaddingException, IllegalBlockSizeException {
        session.putParameter("MessageType", "Session");

        SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
        sessionKey = sessionEncrypter.getKeyBytes();
        sessionIV = sessionEncrypter.getIVBytes();

        String clientPublicKeyPath = this.clientCertificatePath;
        PublicKey clientPublicKey = HandshakeCrypto.getPublicKeyFromCertFile(clientPublicKeyPath);

        byte[] encryptedSessionKey = HandshakeCrypto.encrypt(sessionKey, clientPublicKey);
        byte[] encryptedSessionIV = HandshakeCrypto.encrypt(sessionIV, clientPublicKey);

        byte[] encodedSessionKey = Base64.getEncoder().encode(encryptedSessionKey);
        byte[] encodedSessionIV = Base64.getEncoder().encode(encryptedSessionIV);

        String finalSessionKey = new String(encodedSessionKey);
        String finalSessionIV = new String(encodedSessionIV);

        session.putParameter("SessionKey", finalSessionKey);
        session.putParameter("SessionIV", finalSessionIV);
        session.putParameter("SessionHost", Handshake.serverHost);
        //session.putParameter("SessionPort", String.valueOf(Handshake.serverPort));
        session.putParameter("SessionPort", String.valueOf(sessionPort));

        session.send(socket);
    }

    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */
        HandshakeMessage serverClientHello = new HandshakeMessage();
        clientCheck(serverClientHello, clientSocket);

        serverHello(serverClientHello, clientSocket);

        forwardMessage(serverClientHello, clientSocket);

        int sessionPort = new ServerSocket(0).getLocalPort();
        System.out.println("Session port: " + sessionPort);

        sessionMessage(serverClientHello, clientSocket, sessionPort);
        
        clientSocket.close();

        /*
         * Fake the handshake result with static parameters. 
         */

        /* listenSocket is a new socket where the ForwardServer waits for the 
         * client to connect. The ForwardServer creates this socket and communicates
         * the socket's address to the ForwardClient during the handshake, so that the 
         * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
         * Here, we use a static address instead (serverHost/serverPort). 
         * (This may give "Address already in use" errors, but that's OK for now.)
         */

        // Make dynamic

        listenSocket = new ServerSocket();
        //listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));
        listenSocket.bind(new InetSocketAddress(Handshake.serverHost, sessionPort));

        /* The final destination. The ForwardServer sets up port forwarding
         * between the listensocket (ie., ServerHost/ServerPort) and the target.
         */
        /*
        targetHost = Handshake.targetHost;
        targetPort = Handshake.targetPort;
         */
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
        throws Exception
    {
 
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port + ": " + ioe);
        }

        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
            
            doHandshake();

            SessionEncrypter sessionEncrypter = new SessionEncrypter(Base64.getEncoder().encode(sessionKey),
                    Base64.getEncoder().encode(sessionIV));
            SessionDecrypter sessionDecrypter = new SessionDecrypter(Base64.getEncoder().encode(sessionKey),
                    Base64.getEncoder().encode(sessionIV));

            forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort,
                    sessionEncrypter, sessionDecrypter);
            forwardThread.start();
        }
    }
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
        throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);
        
        ForwardServer srv = new ForwardServer();
        srv.startForwardServer();
    }
}
