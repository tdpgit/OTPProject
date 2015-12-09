
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
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

            System.out.println("Performing key exchange...");

            //get shared key
            BigInteger sharedKey = DHKeyExchange.serverDHKeyExchange(socket);
            System.out.println("negotiated secret : " + sharedKey);

            //get encryption key
            byte[] encryptionKey = EncryptionHelper.createEncryptionKey(password.getBytes(), sharedKey);

            boolean clientConnected = true;
            int sequenceNumber = 0;
            while (clientConnected) {
                //get encrypted message
                int size = socket.getInputStream().read();
                System.out.println("size: " + size);
                byte[] encryptedMessage = new byte[size];
                socket.getInputStream().read(encryptedMessage, 0, size);
                //decrypt the message
                byte[] decryptedMessage = EncryptionHelper.encryptAndDecryptMessage(encryptedMessage, encryptionKey, false);

                //find the integrity hash
                DLSequence dlSequence = (DLSequence)ASN1Primitive.fromByteArray(decryptedMessage);
                byte[] hash = Arrays.copyOfRange(decryptedMessage, dlSequence.getEncoded().length,
                        decryptedMessage.length);

                //get sequence number
                ASN1Integer packetNumber = (ASN1Integer)dlSequence.getObjectAt(1);

                if (packetNumber.getValue().equals(BigInteger.valueOf(sequenceNumber))){
                    //check packet type
                    ASN1Integer packetType = (ASN1Integer)dlSequence.getObjectAt(0);
                    System.out.println("Packet Sequence Number: " + packetNumber);
                    if (packetType.getValue().equals(BigInteger.ONE)) {
                        try {
                            System.out.println("Generate new keys...");
                            sharedKey = DHKeyExchange.serverDHKeyExchange(socket);
                            encryptionKey = EncryptionHelper.createEncryptionKey(password.getBytes(), sharedKey);
                            System.out.println("new shared key: " + sharedKey);
                            sequenceNumber = 0;
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        sequenceNumber += 1;
                        System.out.println("Message: " + new String(((DERBitString)dlSequence.getObjectAt(2)).getBytes()));
                    }
                } else {
                    System.out.println("Incorrect sequence number.");
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