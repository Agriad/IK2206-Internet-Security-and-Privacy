/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * See original copyright notice below.
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
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Base64;

public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;

    private static byte[] sessionKey;
    private static byte[] sessionIV;

    // Creates a HandshakeMessage and returns it filled
    private static HandshakeMessage clientServerHello() throws IOException {
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.putParameter("MessageType", "ClientHello");
        // This works if file already is encoded to string
        // clientHello.putParameter("Certificate", arguments.get("usercert"));

        // If we are sent a file
        // File userCertificateFile = new File(arguments.get("usercert"));

        // If we are sent the name of the file
        String userCertificatePath = "./" + arguments.get("usercert");

        File userCertificateFile = new File(userCertificatePath);
        InputStream userCertificateInputStream = new FileInputStream(userCertificateFile);
        // String userCertificateString = new String(userCertificateInputStream.readAllBytes());
        byte[] userCertificateByte = Base64.getEncoder().encode(userCertificateInputStream.readAllBytes());
        String userCertificateString = new String(userCertificateByte);

        clientHello.putParameter("Certificate", userCertificateString);

        return clientHello;
    }

    // Receives the server hello and verifies it
    private static void serverCheck(HandshakeMessage serverHello, Socket socket) throws IOException,
            CertificateException {
        serverHello.recv(socket);
        String messageType = serverHello.getParameter("MessageType");
        String certificate = serverHello.getParameter("Certificate");

        if (!messageType.equals("ServerHello"))
        {
            throw new IllegalArgumentException("Received: " + messageType + " required: ServerHello");
        }

        byte[] serverCertificateByte = Base64.getDecoder().decode(certificate);
        String serverCertificatePath = "./curent-connection-server.pem";
        File serverCertificateFile = new File(serverCertificatePath);
        FileOutputStream serverFileOutputStream = new FileOutputStream(serverCertificateFile);
        serverFileOutputStream.write(serverCertificateByte);
        serverFileOutputStream.flush();
        serverFileOutputStream.close();

        String caCertificatePath = "./" + arguments.get("cacert");
        File caCertificateFile = new File(caCertificatePath);

        String[] verifyCertificateInput = {caCertificatePath, serverCertificatePath};

        VerifyCertificate.main(verifyCertificateInput);
    }

    // Adds the key value pair for forward message
    private static void forwardMessage(HandshakeMessage forwardMessage, Socket socket) throws IOException {
        forwardMessage.putParameter("MessageType", "Forward");
        forwardMessage.putParameter("TargetHost", arguments.get("targethost"));
        forwardMessage.putParameter("TargetPort", arguments.get("targetport"));

        forwardMessage.send(socket);
    }

    private static void sessionMessage(HandshakeMessage session, Socket socket) throws IOException,
            InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchPaddingException {
        session.recv(socket);
        String messageType = session.getParameter("MessageType");

        if (!messageType.equals("Session"))
        {
            throw new IllegalArgumentException("Received: " + messageType + " required: Session");
        }

        String encodedSessionKey = session.getParameter("SessionKey");
        String encodedSessionIV = session.getParameter("SessionIV");
        String sessionHost = session.getParameter("SessionHost");
        String sessionPort = session.getParameter("SessionPort");

        System.out.println("encodedSessionKey length: " + encodedSessionKey.length() + " value: " + encodedSessionKey);
        System.out.println("encodedSessionIV length: " + encodedSessionIV.length() + " value: " + encodedSessionIV);

        byte[] decodedSessionKey = Base64.getDecoder().decode(encodedSessionKey);
        byte[] decodedSessionIV = Base64.getDecoder().decode(encodedSessionIV);

        String userPrivateKeyPath = "./" + arguments.getProperty("key");
        PrivateKey userPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(userPrivateKeyPath);

        System.out.println("decodedSessionKey length: " + decodedSessionKey.length + " value: " +
                new String(decodedSessionKey));
        System.out.println("decodedSessionIV length: " + decodedSessionIV.length + " value: " +
                new String(encodedSessionIV));

        byte[] decryptedSessionKey = HandshakeCrypto.decrypt(decodedSessionKey, userPrivateKey);
        byte[] decryptedSessionIV = HandshakeCrypto.decrypt(decodedSessionIV, userPrivateKey);

        serverHost = sessionHost;
        serverPort = Integer.getInteger(sessionPort);

        sessionKey = decryptedSessionKey;
        sessionIV = decryptedSessionIV;
    }

    private static void doHandshake() throws IOException, CertificateException, BadPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException,
            InvalidKeySpecException {

        /* Connect to forward server server */
        System.out.println("Connect to " +  arguments.get("handshakehost") + ":" +
                Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */
        HandshakeMessage clientServerHello = clientServerHello();
        clientServerHello.send(socket);

        serverCheck(clientServerHello, socket);

        forwardMessage(clientServerHello, socket);

        sessionMessage(clientServerHello, socket);

        socket.close();

        /*
         * Fake the handshake result with static parameters.
         */

        /* This is to where the ForwardClient should connect. 
         * The ForwardServer creates a socket
         * dynamically and communicates the address (hostname and port number)
         * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
         * Here, we use a static address instead. 
         */
        /*
        serverHost = Handshake.serverHost;
        serverPort = Handshake.serverPort;
         */
    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" +
                arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws IOException, CertificateException, BadPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException,
            InvalidKeySpecException, InvalidAlgorithmParameterException {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        
        /* Create a new socket. This is to where the user should connect.
         * ForwardClient sets up port forwarding between this socket
         * and the ServerHost/ServerPort learned from the handshake */
        listensocket = new ServerSocket();
        /* Let the system pick a port number */
        listensocket.bind(null); 
        /* Tell the user, so the user knows where to connect */ 
        tellUser(listensocket);

        Socket clientSocket = listensocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        log("Accepted client from " + clientHostPort);

        SessionEncrypter sessionEncrypter = new SessionEncrypter(Base64.getEncoder().encode(sessionKey),
                Base64.getEncoder().encode(sessionIV));
        SessionDecrypter sessionDecrypter = new SessionDecrypter(Base64.getEncoder().encode(sessionKey),
                Base64.getEncoder().encode(sessionIV));

        forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort,
                sessionEncrypter, sessionDecrypter);
        forwardThread.start();
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) throws IOException, CertificateException, BadPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException,
            InvalidKeySpecException, InvalidAlgorithmParameterException {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        startForwardClient();
    }
}
