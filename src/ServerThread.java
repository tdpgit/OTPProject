
import java.math.BigInteger;
import java.net.Socket;
import java.security.Security;

/**
 * Created by Trevor on 12/7/15.
 */
class ServerThread extends Thread {
    private Socket socket;

    /**
     * @param socket
     */
    public ServerThread(Socket socket) {
        this.socket = socket;
    }

    /**
     * run thread
     */
    public void run() {
        try {
            System.out.println("Client Connected.");

            //use bouncy castle
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            BigInteger sharedKey = DHKeyExchange.serverDHKeyExchange(socket);

            System.out.println("agreement: " + sharedKey);

            //close socket
            System.out.println("Close Socket.");

            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}