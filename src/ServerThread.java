
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLSequence;

import java.math.BigInteger;
import java.net.Socket;
import java.security.Security;
import java.util.Arrays;

/**
 * Created by Trevor on 12/7/15.
 */
class ServerThread extends Thread {
    private Socket socket;
    private String password;

    public ServerThread(Socket socket, String password) {
        this.socket = socket;
        this.password = password;
    }


    public void run() {
        try {
            System.out.println("Client Connected.");

            //use bouncy castle
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            System.out.println("Perform key exchange.");

            //get shared key
            BigInteger sharedKey = DHKeyExchange.serverDHKeyExchange(socket);
            System.out.println("agreement: " + sharedKey);

            //get encryption key
            byte[] encryptionKey = EncryptionHelper.createEncryptionKey(password.getBytes(), sharedKey);
            System.out.println("encryption key: " + encryptionKey);

            boolean clientConnected = true;
            while (clientConnected) {
                //get encrypted message
                int size = socket.getInputStream().read();
                System.out.println("size: " + size);
                byte[] encryptedMessage = new byte[size];
                socket.getInputStream().read(encryptedMessage, 0, size);
                System.out.println("encrypted message: " + encryptedMessage);
                //decrypt the message
                byte[] decryptedMessage = EncryptionHelper.encryptAndDecryptMessage(encryptedMessage, encryptionKey, false);
                System.out.println("encrypted message: " + decryptedMessage);

                //find the integrity hash
                DLSequence dlSequence = (DLSequence)ASN1Primitive.fromByteArray(decryptedMessage);
                byte[] hash = Arrays.copyOfRange(decryptedMessage, dlSequence.getEncoded().length,
                        decryptedMessage.length);

                //check packet type
                ASN1Integer packetType = (ASN1Integer)dlSequence.getObjectAt(0);
                if (packetType.equals(BigInteger.ONE)) {
                    try {
                        sharedKey = DHKeyExchange.serverDHKeyExchange(socket);
                        encryptionKey = EncryptionHelper.createEncryptionKey(password.getBytes(), sharedKey);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    System.out.println("The impossible" + new String(dlSequence.getObjectAt(2).toASN1Primitive().getEncoded()));
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            //close socket
            System.out.println("Close Socket.");
            try {
                socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}