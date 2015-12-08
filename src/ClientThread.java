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
import java.util.Scanner;

/**
 * Created by Trevor on 12/7/15.
 */
public class ClientThread extends Thread {
    private String host;
    private int port;
    private String password;
    private Socket socket;

    public ClientThread(String host, int port, String password) {
        this.host = host;
        this.port = port;
        this.password = password;
    }

    private void sendPacket(SecurePacket securePacket, BigInteger sharedKey, byte[] encryptionKey) throws Exception {
        //create FinalPacket
        FinalPacket finalPacket = new FinalPacket();
        finalPacket.message = securePacket.toASN1Primitive().getEncoded("DER");

        //get integrity hash
        byte[] integrityHash = EncryptionHelper.createHashIntegrity(finalPacket.message, sharedKey.toByteArray());
        System.out.println("hashintegrity: " + integrityHash);

        //add to final packet
        finalPacket.integrityHash = integrityHash;

        //combine key and hash integrity
        byte[] finalData = finalPacket.getCombinedData();

        //get encrypted message
        byte[] encryptedData = EncryptionHelper.encryptAndDecryptMessage(finalData, encryptionKey,
                true);
        System.out.println("encrypted message: " + encryptedData);

        System.out.println("size: " + finalPacket.getSize() + "other: "  + encryptedData.length);
        socket.getOutputStream().write(encryptedData.length);
        socket.getOutputStream().write(encryptedData, 0, encryptedData.length);
    }

    public void run() {
        try {
            socket = new Socket(host, port);

            System.out.println("Perform Key Exchange.");

            //get shared key
            BigInteger sharedKey = DHKeyExchange.clientDHKeyExchange(socket);
            System.out.println("agreement:" + sharedKey);

            //get aes encryption key
            byte[] encryptionKey = EncryptionHelper.createEncryptionKey(password.getBytes(), sharedKey);
            System.out.println("encryption key: " + encryptionKey);

            boolean clientConnected = true;
            while (clientConnected) {

                //request command
                System.out.print("Enter \"send\" or \"rekey\" command: ");
                Scanner scanner = new Scanner(System.in);
                String command = scanner.next();

                //create secure packet
                SecurePacket securePacket = new SecurePacket();
                securePacket.packetType = 2;
                securePacket.data = "I love fries".getBytes();
                securePacket.sequenceNumber = 0;
                securePacket.base = new byte[0];
                securePacket.prime = new byte[0];

                //check task to perform
                if (command.equals("send")) {
                    System.out.print("Enter message: ");
                    String message = scanner.next();
                    securePacket.packetType = 2;
                    securePacket.data = message.getBytes();
                    sendPacket(securePacket, sharedKey, encryptionKey);
                } else if (command.equals("rekey")){
                    securePacket.packetType = 1;
                    securePacket.data = new byte[0];
                    sendPacket(securePacket, sharedKey, encryptionKey);
                    try {
                        sharedKey = DHKeyExchange.clientDHKeyExchange(socket);
                        encryptionKey = EncryptionHelper.createEncryptionKey(password.getBytes(), sharedKey);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    System.out.println("Unrecognized command. Try again.");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                System.out.println("Ending Connection.");
                socket.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

}
