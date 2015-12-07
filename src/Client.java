import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x9.DHPublicKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

import javax.crypto.KeyAgreement;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;

public class Client {
    public static void main(String[] args) throws Exception {


        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        int portno = 3000;
        byte[] otpkey = {(byte)0xAA,(byte)0xAA, (byte)0xAA, (byte)0xAA};
        String hostaddress = "localhost";
        String message = "This is my default message";

        //try to set values through args
        try {
            portno = Integer.parseInt(args[0]);
            hostaddress = args[1];
            otpkey = DatatypeConverter.parseHexBinary(args[2]);
            message = args[3];
            for(int i = 4; i < args.length; i++) {
                message = message + " " + args[i];
            }
        } catch (Exception e) {
            //use defaults
        }

        //try connecting to server
        try {
            //get ip address
            InetAddress address = InetAddress.getByName(hostaddress);

            //create socket
            Socket socket = new Socket(address, portno);

            //key generator
            SecureRandom secureRandom = new SecureRandom();
            DHParametersGenerator dhParametersGenerator = new DHParametersGenerator();
            dhParametersGenerator.init(512, 100, secureRandom);

            DHParameters dhParameters = dhParametersGenerator.generateParameters();

            DHBasicKeyPairGenerator dhBasicKeyPairGenerator = new DHBasicKeyPairGenerator();
            DHKeyGenerationParameters dhKeyGenerationParameters = new DHKeyGenerationParameters(secureRandom,
                    dhParameters);
            dhBasicKeyPairGenerator.init(dhKeyGenerationParameters);

            AsymmetricCipherKeyPair asymmetricCipherKeyPair =  dhBasicKeyPairGenerator.generateKeyPair();

            DHPublicKeyParameters dhPublicKeyParameters = (DHPublicKeyParameters)asymmetricCipherKeyPair.getPublic();

            DHBasicAgreement dhBasicAgreement = new DHBasicAgreement();
            dhBasicAgreement.init(asymmetricCipherKeyPair.getPrivate());


            //create packet
            SecurePacket securePacket = new SecurePacket();
            securePacket.packetType = 1;
            securePacket.sequenceNumber = 0;
            securePacket.publicKey = dhPublicKeyParameters.getY().toByteArray();
            BigInteger bigInteger = new BigInteger(securePacket.publicKey);
            System.out.println(bigInteger);
            securePacket.prime = dhParameters.getP().toByteArray();
            securePacket.base = dhParameters.getG().toByteArray();

            ASN1OutputStream out = new ASN1OutputStream(socket.getOutputStream());
            out.writeObject(securePacket.toASN1Primitive());

            System.out.println("Sent packet");

            ASN1InputStream asn1InputStream = new ASN1InputStream(socket.getInputStream());
            DLSequence dlSequence = (DLSequence)asn1InputStream.readObject();

            DERBitString derBitString = (DERBitString)dlSequence.getObjectAt(2);
            BigInteger publicKey = new BigInteger(derBitString.getBytes());

            DHPublicKeyParameters serverKey = new DHPublicKeyParameters(publicKey, dhParameters);

            BigInteger agreement = dhBasicAgreement.calculateAgreement(serverKey);

            System.out.println("agreement:" + agreement);

            System.out.println("Ending Connection.");
            socket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
