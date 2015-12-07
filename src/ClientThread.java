import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;

/**
 * Created by Trevor on 12/7/15.
 */
public class ClientThread extends Thread {
    private String host;
    private int port;
    private Socket socket;

    public ClientThread(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void run() {
        try {
            socket = new Socket(host, port);

            BigInteger sharedKey = DHKeyExchange.clientDHKeyExchange(socket);

            System.out.println("agreement:" + sharedKey);

            System.out.println("Ending Connection.");
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
