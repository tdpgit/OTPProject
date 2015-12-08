
import java.security.*;

public class Client {
    public static void main(String[] args) throws Exception {


        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        int portno = 3000;
        String hostaddress = "localhost";

        new ClientThread(hostaddress, portno).start();

    }
}
