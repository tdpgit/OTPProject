import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by Trevor on 12/7/15.
 */
public class EncryptionHelper {

    public static byte[] createEncryptionKey(byte[] sharedPassword, BigInteger sharedKey) throws Exception {

        //seed secure random
        SecureRandom secureRandom = new SecureRandom(sharedPassword);
        BigInteger nonce = new BigInteger(256, secureRandom);  //create nonce

        //combine nonce and shared key
        ByteArrayOutputStream combinedKey = new ByteArrayOutputStream();
        combinedKey.write(nonce.toByteArray());
        combinedKey.write(sharedKey.toByteArray());

        //create sha256 key
        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(combinedKey.toByteArray(), 0, combinedKey.toByteArray().length);

        //create final key value
        byte[] key = new byte[32];
        sha256.doFinal(key, 0);

        return key;
    }

    public static byte[] encryptAndDecryptMessage(byte[] message, byte[] encryptionKey, boolean encrypt) throws Exception {
        //seed secureRandom with key
        SecureRandom secureRandom = new SecureRandom(encryptionKey);
        //prepare aes
        AESEngine aesEngine = new AESEngine();
        CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(aesEngine);
        PaddedBufferedBlockCipher paddedBufferedBlockCipher = new PaddedBufferedBlockCipher(cbcBlockCipher);
        byte[] initVect = new byte[aesEngine.getBlockSize()];
        secureRandom.nextBytes(initVect);
        //use key for cipher params
        KeyParameter keyParameter = new KeyParameter(encryptionKey);
        CipherParameters cipherParameters = new ParametersWithIV(keyParameter, initVect);
        paddedBufferedBlockCipher.init(encrypt, cipherParameters);
        //get encryption
        int size = paddedBufferedBlockCipher.getOutputSize(message.length);
        byte[] encryptedMessage = new byte[size];
        int processedBytesLength = paddedBufferedBlockCipher.processBytes(message, 0, message.length,
                encryptedMessage, 0);
        paddedBufferedBlockCipher.doFinal(encryptedMessage, processedBytesLength);
        return encryptedMessage;
    }

    public static byte[] createHashIntegrity(byte[] message, byte[] sharedKey) {
        //create hmac
        SHA256Digest sha256Digest = new SHA256Digest();
        HMac hMac = new HMac(sha256Digest);
        //get result
        KeyParameter keyParameter = new KeyParameter(sharedKey); //key
        hMac.init(keyParameter); //intitialize with key
        hMac.update(message, 0, message.length); //update with message
        byte[] hashIntegrity = new byte[hMac.getMacSize()]; //store in hashIntegrity
        hMac.doFinal(hashIntegrity, 0);
        return hashIntegrity;
    }

}
