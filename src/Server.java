
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;

public class Server {

    public static void main(String[] args) {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        boolean serverRunning = true;
        int portno = 3000;
        //try to set port and otp
//        try {
//            portno = Integer.parseInt(args[0]);
//            otpkey = DatatypeConverter.parseHexBinary(args[1]);
//        } catch(Exception e) {
//           //use defaults
//        }

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

