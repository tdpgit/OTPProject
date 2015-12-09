import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.io.Serializable;

/**
 * Created by Trevor on 11/30/15.
 */
public class SecurePacket implements ASN1Encodable  {
    int packetType;
    int sequenceNumber;
    byte[] data;
    byte[] prime;
    byte[] base;

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{new ASN1Integer(packetType), new ASN1Integer(sequenceNumber),
                new DERBitString(data), new DERBitString(prime), new DERBitString(base)});
    }
}
