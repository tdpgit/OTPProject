
import java.security.*;

public class Client {
    public static void main(String[] args) throws Exception {


        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        int portno = 3000;
        String hostaddress = "localhost";

        new ClientThread(hostaddress, portno).start();

        //try to set values through args
//        try {
//            portno = Integer.parseInt(args[0]);
//            hostaddress = args[1];
//
//        } catch (Exception e) {
//            //use defaults
//        }


    }
}
