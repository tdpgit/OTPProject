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
    private String message = "I love fries";
    private String password = "shared";
    private Socket socket;

    public ClientThread(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void run() {
        try {
            socket = new Socket(host, port);

            //get shared key
            BigInteger sharedKey = DHKeyExchange.clientDHKeyExchange(socket);
            System.out.println("agreement:" + sharedKey);

            //create secure packet
            SecurePacket securePacket = new SecurePacket();
            securePacket.packetType = 2;
            securePacket.sequenceNumber = 0;
            securePacket.data = message.getBytes();
            securePacket.base = new byte[0];
            securePacket.prime = new byte[0];

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

            //get aes encryption key
            byte[] encryptionKey = EncryptionHelper.createEncryptionKey(password.getBytes(), sharedKey);
            System.out.println("encryption key: " + encryptionKey);

            //get encrypted message
            byte[] encryptedData = EncryptionHelper.encryptAndDecryptMessage(finalData, encryptionKey,
                    true);
            System.out.println("encrypted message: " + encryptedData);

            System.out.println("size: " + finalPacket.getSize());
            socket.getOutputStream().write(finalPacket.getSize());
            socket.getOutputStream().write(encryptedData, 0, encryptedData.length);

            System.out.println("Ending Connection.");
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
