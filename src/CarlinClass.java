//package Utility;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.xml.bind.DatatypeConverter;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.math.BigInteger;
import java.net.*;

public class CarlinClass {

    private static final int DH_KEY_SIZE = 512;
    private static final int DEFAULT_PRIME_CERTAINTY = 100;
    private static final SHA256Digest SHA256 = new SHA256Digest();
    private static final HMac hmac = new HMac(SHA256);
    private static final SecureRandom secRandom = new SecureRandom();

    public static void addSecurityProviderBC() {Security.addProvider(new BouncyCastleProvider());}

    public static byte[] hashHMACSHA256(byte[] message, byte[] key) {
        byte[] result = new byte[hmac.getMacSize()];
        byte[] msgArray = message;
        KeyParameter kp = new KeyParameter(key);
        hmac.init(kp);
        hmac.update(msgArray,0,msgArray.length);
        hmac.doFinal(result,0);
        return result;
    }

    public static byte[] cipherData(PaddedBufferedBlockCipher cipher, byte[] message) throws InvalidCipherTextException {
        int cipherOutputSize = cipher.getOutputSize(message.length);
        byte[] cipherOutput = new byte[cipherOutputSize];
        int processedBytesLength = cipher.processBytes(message, 0, message.length, cipherOutput, 0);
        cipher.doFinal(cipherOutput, processedBytesLength);
        return cipherOutput;
    }

    public static byte[] encryptCBCAES256(byte[] message, byte[] key) throws InvalidCipherTextException {
        SecureRandom secureRandom = new SecureRandom(key);
        AESEngine aesEngine = new AESEngine();
        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(aesEngine));
        byte[] IV = new byte[aesEngine.getBlockSize()];
        secureRandom.nextBytes(IV);
        debug("IV is: " + DatatypeConverter.printHexBinary(IV));
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), IV);
        aes.init(true, ivAndKey);
        return cipherData(aes, message);
    }

    public static byte[] decryptCBCAES256(byte[] message, byte[] key) throws InvalidCipherTextException {
        SecureRandom secureRandom = new SecureRandom(key);
        AESEngine aesEngine = new AESEngine();
        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(aesEngine));
        byte[] IV = new byte[aesEngine.getBlockSize()];
        secureRandom.nextBytes(IV);
        debug("IV is: " + DatatypeConverter.printHexBinary(IV));
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), IV);
        aes.init(false, ivAndKey);
        return cipherData(aes, message);
    }

    public static byte[] SaltandHashSHA256toKey(String passphrase, BigInteger DHKey) {
        SecureRandom secureRandom = new SecureRandom(passphrase.getBytes());
        BigInteger nonce = new BigInteger(256, secureRandom);
        System.out.println("NONCE is: " + nonce);
        //Merges byte arrays into one array for hashing
        byte[] preimagekey = new byte[nonce.toByteArray().length + DHKey.toByteArray().length];
        System.arraycopy(nonce.toByteArray(), 0, preimagekey, 0, nonce.toByteArray().length);
        System.arraycopy(DHKey.toByteArray(), 0, preimagekey, nonce.toByteArray().length, nonce.toByteArray().length);
        SHA256.update(preimagekey, 0, preimagekey.length);
        byte[] result = new byte[32];
        SHA256.doFinal(result, 0);
        System.out.println("Calculated SHA256 hash of nonce + DH shared key, ready for messaging");
        return result;
    }

    private static DHParameters dhParametersSaved = null;

    public static BigInteger serverDHKeyExchange(Socket socket) throws Exception {
        System.err.println("New client starting...");
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        //Generating DH Parameters can take quite a while so generate parameters
        // once on startup and then just generate new keys from that
        // generating parameters on server I think would help prevent malicious
        // clients from being able to control the DH agreement via picking P and G
        DHParameters dhParameters;
        if (dhParametersSaved == null) {
            System.out.println("Generating DH parameters to be used on client and server...");
            DHParametersGenerator dhParametersGenerator = new DHParametersGenerator();
            dhParametersGenerator.init(DH_KEY_SIZE, DEFAULT_PRIME_CERTAINTY, secRandom);
            dhParameters = dhParametersGenerator.generateParameters();
            dhParametersSaved = dhParameters;
            System.out.println("Prime modulus will be " + dhParameters.getP());
            System.out.println("Generator will be " + dhParameters.getG());
        } else {
            dhParameters = dhParametersSaved;
        }

        System.out.println("Generating key pair with DH params...");
        DHBasicKeyPairGenerator dhBasicKeyPairGenerator = new DHBasicKeyPairGenerator();
        DHKeyGenerationParameters dhKeyGenerationParameters = new DHKeyGenerationParameters(secRandom, dhParameters);
        dhBasicKeyPairGenerator.init(dhKeyGenerationParameters);
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = dhBasicKeyPairGenerator.generateKeyPair();
        AsymmetricKeyParameter pub = asymmetricCipherKeyPair.getPublic();
        DHPublicKeyParameters dhPublicKeyParameters = (DHPublicKeyParameters) pub;
        System.out.println("Server public key is :" + ((DHPublicKeyParameters) pub).getY());

        System.out.println("Initializing agreement with new private key...");
        DHBasicAgreement dhBasicAgreement = new DHBasicAgreement();
        dhBasicAgreement.init(asymmetricCipherKeyPair.getPrivate());

        System.out.println("Sending generated DH params and pub key to client...");
        out.write(dhPublicKeyParameters.getY().toByteArray().length);
        out.write(dhPublicKeyParameters.getY().toByteArray());
        out.write(dhParameters.getP().toByteArray().length);
        out.write(dhParameters.getP().toByteArray());
        out.write(dhParameters.getG().toByteArray().length);
        out.write(dhParameters.getG().toByteArray());

        System.out.println("Receiving client pub key...");
        int foreign_pub_length = in.read();
        byte[] foreign_pub = new byte[foreign_pub_length];
        in.read(foreign_pub);

        System.out.println("Finishing agreement using client pub key");
        DHPublicKeyParameters foreignDHPublicKeyParameters = new DHPublicKeyParameters( new BigInteger(foreign_pub), dhParameters);
        BigInteger secret = dhBasicAgreement.calculateAgreement(foreignDHPublicKeyParameters);
        System.out.println("Calculated key exchange, shared key is:");
        System.out.println(secret);
        return secret;
    }

    public static BigInteger clientDHKeyExchange(Socket socket) throws Exception {
        System.out.println("Starting...");
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        System.out.println("Waiting for DH params and pub key from server...");
        int foreign_pub_length = in.read();
        byte[] foreign_pub = new byte[foreign_pub_length];
        in.read(foreign_pub);
        int foreign_P_length = in.read();
        byte[] foreign_P = new byte[foreign_P_length];
        in.read(foreign_P);
        int foreign_G_length = in.read();
        byte[] foreign_G = new byte[foreign_G_length];
        in.read(foreign_G);
        DHParameters foreignDHParameters =  new DHParameters( new BigInteger(foreign_P), new BigInteger(foreign_G));
        DHPublicKeyParameters foreignDHPublicKeyParameters = new DHPublicKeyParameters( new BigInteger(foreign_pub), foreignDHParameters);

        System.out.println("Generating key pair with foreign DH params...");
        DHBasicKeyPairGenerator dhBasicKeyPairGenerator = new DHBasicKeyPairGenerator();
        DHKeyGenerationParameters dhKeyGenerationParameters = new DHKeyGenerationParameters(secRandom, foreignDHParameters);
        dhBasicKeyPairGenerator.init(dhKeyGenerationParameters);
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = dhBasicKeyPairGenerator.generateKeyPair();
        AsymmetricKeyParameter pub = asymmetricCipherKeyPair.getPublic();
        DHPublicKeyParameters dhPublicKeyParameters = (DHPublicKeyParameters) pub;
        System.out.println("Client public key is: " + pub);

        System.out.println("Initializing agreement with new private key...");
        DHBasicAgreement dhBasicAgreement = new DHBasicAgreement();
        dhBasicAgreement.init(asymmetricCipherKeyPair.getPrivate());

        System.out.println("Sending public key to server...");
        out.write(dhPublicKeyParameters.getY().toByteArray().length);
        out.write(dhPublicKeyParameters.getY().toByteArray());

        System.out.println("Finishing agreement using foreign DH params and pub key");

        BigInteger secret = dhBasicAgreement.calculateAgreement(foreignDHPublicKeyParameters);
        System.out.println("Calculated key exchange, shared key is:");
        System.out.println(secret);
        return secret;
    }

    public static final boolean debug_mode = false;
    public static void debug(String message) {
        if (debug_mode == true) {
            System.out.println(message);
        }
    }
}
