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
public class DHKeyExchange {

    public static BigInteger clientDHKeyExchange(Socket socket) throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        //generator for prime mod and base generator
        DHParametersGenerator dhParametersGenerator = new DHParametersGenerator();
        dhParametersGenerator.init(512, 100, secureRandom);

        //generate mod and base
        DHParameters dhParameters = dhParametersGenerator.generateParameters();

        //key pair generator
        DHBasicKeyPairGenerator dhBasicKeyPairGenerator = new DHBasicKeyPairGenerator();
        DHKeyGenerationParameters dhKeyGenerationParameters = new DHKeyGenerationParameters(secureRandom,
                dhParameters);
        dhBasicKeyPairGenerator.init(dhKeyGenerationParameters); //give key generator mod and base

        //generate keyPair for client
        AsymmetricCipherKeyPair asymmetricCipherKeyPair =  dhBasicKeyPairGenerator.generateKeyPair();
        //get public key to send to server
        DHPublicKeyParameters dhPublicKeyParameters = (DHPublicKeyParameters)asymmetricCipherKeyPair.getPublic();

        //provide private key for shared key
        DHBasicAgreement dhBasicAgreement = new DHBasicAgreement();
        dhBasicAgreement.init(asymmetricCipherKeyPair.getPrivate());

        //create packet to send to server
        SecurePacket securePacket = new SecurePacket();
        securePacket.packetType = 1;
        securePacket.sequenceNumber = 0;
        securePacket.publicKey = dhPublicKeyParameters.getY().toByteArray();
        securePacket.prime = dhParameters.getP().toByteArray();
        securePacket.base = dhParameters.getG().toByteArray();

        //send to server
        ASN1OutputStream out = new ASN1OutputStream(socket.getOutputStream());
        out.writeObject(securePacket.toASN1Primitive());
        System.out.println("Sent Key Exchange Packet");

        //read from server
        ASN1InputStream asn1InputStream = new ASN1InputStream(socket.getInputStream());
        DLSequence dlSequence = (DLSequence)asn1InputStream.readObject();

        //get public key of server
        DERBitString derBitString = (DERBitString)dlSequence.getObjectAt(2);
        BigInteger publicKey = new BigInteger(derBitString.getBytes());

        DHPublicKeyParameters serverKey = new DHPublicKeyParameters(publicKey, dhParameters); //convert bytes to key
        //provide server public and return shared key
        return dhBasicAgreement.calculateAgreement(serverKey);
    }

    public static BigInteger serverDHKeyExchange(Socket socket) throws Exception {
        //recieve public key, mod, and base from client
        ASN1InputStream in = new ASN1InputStream(socket.getInputStream());
        DLSequence dlSequence = (DLSequence)in.readObject();

        //convert key exchange factors to BigInteger values
        DERBitString publicKeyString = (DERBitString)dlSequence.getObjectAt(2);
        DERBitString primeString = (DERBitString)dlSequence.getObjectAt(3);
        DERBitString baseString = (DERBitString)dlSequence.getObjectAt(4);
        BigInteger clientKey = new BigInteger(publicKeyString.getBytes());
        BigInteger prime = new BigInteger(primeString.getBytes());
        BigInteger base = new BigInteger(baseString.getBytes());

        //key pair generator
        DHBasicKeyPairGenerator dhBasicKeyPairGenerator = new DHBasicKeyPairGenerator();
        DHParameters dhParameters = new DHParameters(prime, base); //use prime and base from client
        DHKeyGenerationParameters dhKeyGenerationParameters = new DHKeyGenerationParameters(new SecureRandom(), dhParameters);
        dhBasicKeyPairGenerator.init(dhKeyGenerationParameters);
        //generate server key pair
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = dhBasicKeyPairGenerator.generateKeyPair();

        //use private key for shared key
        DHBasicAgreement dhAgreement = new DHBasicAgreement();
        dhAgreement.init(asymmetricCipherKeyPair.getPrivate());
        //convert client key byte[] to key
        DHPublicKeyParameters publicKey = new DHPublicKeyParameters(clientKey, dhParameters);
        //find shared key
        BigInteger sharedKey = dhAgreement.calculateAgreement(publicKey);

        ASN1OutputStream out = new ASN1OutputStream(socket.getOutputStream());
        SecurePacket securePacket = new SecurePacket();

        //create and send packet with public key of server
        DHPublicKeyParameters dhPublicKeyParameters = (DHPublicKeyParameters)asymmetricCipherKeyPair.getPublic();
        securePacket.sequenceNumber = 0;
        securePacket.packetType = 1;
        securePacket.publicKey = dhPublicKeyParameters.getY().toByteArray();
        securePacket.base = new byte[0];
        securePacket.prime = new byte[0];

        out.writeObject(securePacket.toASN1Primitive());

        //return shared key
        return sharedKey;
    }

}
