import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.agreement.DHAgreement;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

public class Server {

    public static void main(String[] args) {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        boolean serverRunning = true;
        int portno = 3000;
        byte[] otpkey = {(byte)0xAA,(byte)0xAA, (byte)0xAA, (byte)0xAA};
        //try to set port and otp
        try {
            portno = Integer.parseInt(args[0]);
            otpkey = DatatypeConverter.parseHexBinary(args[1]);
        } catch(Exception e) {
           //use defaults
        }

        try {
            //create socket
            ServerSocket server = new ServerSocket(portno);


            //listen while server runs
            while(serverRunning) {
                //accept clients and start thread
                Socket socket = server.accept();
                new ProxyThread(socket, otpkey).start();
            }

        } catch(Exception e) {
            e.printStackTrace();
        }

    }
}

class ProxyThread extends Thread {
    private Socket socket;
    private byte[] otpkey;
    public ProxyThread(Socket socket, byte[] otpkey) {
        this.socket = socket;
        this.otpkey = otpkey;
    }

    public void run() {
        try {
            System.out.println("Client Connected.");
            //get input
//            InputStream is = socket.getInputStream();
            int readSize;

            //use bouncycastle
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            //recieve public key from client
//            byte[] ckey = new byte[256];
//            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            ASN1InputStream in = new ASN1InputStream(socket.getInputStream());
            DLSequence dlSequence = (DLSequence)in.readObject();

            DERBitString publicKeyString = (DERBitString)dlSequence.getObjectAt(2);
            DERBitString primeString = (DERBitString)dlSequence.getObjectAt(3);
            DERBitString baseString = (DERBitString)dlSequence.getObjectAt(4);
            BigInteger clientKey = new BigInteger(publicKeyString.getBytes());
            BigInteger prime = new BigInteger(primeString.getBytes());
            BigInteger base = new BigInteger(baseString.getBytes());

            DHBasicKeyPairGenerator dhBasicKeyPairGenerator = new DHBasicKeyPairGenerator();
            DHParameters dhParameters = new DHParameters(prime, base);
            DHKeyGenerationParameters dhKeyGenerationParameters = new DHKeyGenerationParameters(new SecureRandom(), dhParameters);
            dhBasicKeyPairGenerator.init(dhKeyGenerationParameters);
            AsymmetricCipherKeyPair asymmetricCipherKeyPair = dhBasicKeyPairGenerator.generateKeyPair();

            DHBasicAgreement dhAgreement = new DHBasicAgreement();
            dhAgreement.init(asymmetricCipherKeyPair.getPrivate());

            DHPublicKeyParameters publicKey = new DHPublicKeyParameters(clientKey, dhParameters);

            BigInteger agreement = dhAgreement.calculateAgreement(publicKey);

            System.out.println("agreement: " + agreement);

            ASN1OutputStream out = new ASN1OutputStream(socket.getOutputStream());
            SecurePacket securePacket = new SecurePacket();

            DHPublicKeyParameters dhPublicKeyParameters = (DHPublicKeyParameters)asymmetricCipherKeyPair.getPublic();
            securePacket.sequenceNumber = 0;
            securePacket.packetType = 1;
            securePacket.publicKey = dhPublicKeyParameters.getY().toByteArray();
            securePacket.base = new byte[0];
            securePacket.prime = new byte[0];

            out.writeObject(securePacket.toASN1Primitive());
//            BigInteger bigInteger = ;

//            System.out.println(bigInteger);

//            SecurePacket securePacket = (SecurePacket)asn1Primitive;
//            DLSequence derSequence = (DLSequence)in.readObject();
//            SecurePacket securePacket = (SecurePacket)dlSequence.getObjectAt(0);
//            BigInteger publicKey = new BigInteger(securePacket.publicKey);
//            BigInteger prime = new BigInteger(securePacket.prime);
//            BigInteger base = new BigInteger(securePacket.base);


//            System.out.println("public:" + publicKey + "prime:" + prime + "base:" + base);
//            SecurePacket securePacket = (SecurePacket) is.readObject();
//            System.out.println(new String(ckey));
//            ASN1InputStream in = new ASN1InputStream(is);
//            ASN1Primitive clientObject = in.readObject();
//            SecurePacket securePacket = clientObject
//            System.out.println(new String(securePacket.payload));

            //find length of message
//            byte[] messageLength = new byte[4];
//            ByteArrayOutputStream messageLengthHolder = new ByteArrayOutputStream();
//            while((readSize = is.read(messageLength, 0, messageLength.length)) > 0) {
//                messageLengthHolder.write(messageLength, 0, readSize);
//
//                if(messageLengthHolder.toByteArray().length == 4) {
//                    break;
//                }
//            }
//            is.read(messageLength, 0, messageLength.length);
//            messageLength = messageLengthHolder.toByteArray();
//            int holdLength = ByteBuffer.wrap(messageLength).getInt();
//            System.out.println("Message Length: " + holdLength);

            //find rest of message
//            byte[] encodedMessage = new byte[holdLength];
//            ByteArrayOutputStream encodedMessageHolder = new ByteArrayOutputStream();
//            while((readSize = is.read(encodedMessage, 0, holdLength)) > 0) {
//                encodedMessageHolder.write(encodedMessage, 0, readSize);
//
//                if(encodedMessageHolder.toByteArray().length == holdLength) {
//                    break;
//                }
//            }
//            //            is.read(encodedMessage, 0, holdLength);
//            encodedMessage = encodedMessageHolder.toByteArray();

            //decode message
//            final byte[] decoded = new byte[encodedMessage.length];
//            final byte[] key = new byte[encodedMessage.length];
//            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
//            sr.setSeed(otpkey);
//            sr.nextBytes(key);
//            for(int i = 0; i < encodedMessage.length; i++) {
//                decoded[i] = (byte)(encodedMessage[i] ^ key[i]);
//            }

            //confirm the message was recieved
//            OutputStream os = socket.getOutputStream();
//            String returnMessage = "I got the message.";
//            os.write(returnMessage.getBytes(), 0, returnMessage.getBytes().length);

            //close socket
            System.out.println("Close Socket.");

            //important info to print
//            System.out.println("Important: ");
//            System.out.println("client IP address: " + socket.getRemoteSocketAddress());
//            System.out.println("ciphertext: " + DatatypeConverter.printHexBinary(encodedMessageHolder.toByteArray()));
//            System.out.println("Plaintext: " + new String(decoded));

            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
