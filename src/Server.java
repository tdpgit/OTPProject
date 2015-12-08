
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;

public class Server {

    public static void main(String[] args) {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        boolean serverRunning = true;
        int portno = 3000;

        try {
            //create socket
            ServerSocket server = new ServerSocket(portno);


            //listen while server runs
            while(serverRunning) {
                //accept clients and start thread
                Socket socket = server.accept();
                new ServerThread(socket).start();
            }

        } catch(Exception e) {
            e.printStackTrace();
        }

    }
}

