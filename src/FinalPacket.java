import org.bouncycastle.asn1.*;

import java.io.ByteArrayOutputStream;

/**
 * Created by Trevor on 12/7/15.
 */
public class FinalPacket  {
    public int size;
    public byte[] message;
    public byte[] integrityHash;

    public int getSize() {
        size = message.length + integrityHash.length;
        return size;
    }

    public byte[] getCombinedData() throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(message);
        byteArrayOutputStream.write(integrityHash);
        return  byteArrayOutputStream.toByteArray();
    }
}
