package com.mi.car.jsse.easysec.jce;

import com.mi.car.jsse.easysec.asn1.ASN1Encoding;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.pkcs.ContentInfo;
import com.mi.car.jsse.easysec.asn1.pkcs.MacData;
import com.mi.car.jsse.easysec.asn1.pkcs.Pfx;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.DigestInfo;
import java.io.IOException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class PKCS12Util {
    public static byte[] convertToDefiniteLength(byte[] berPKCS12File) throws IOException {
        return Pfx.getInstance(berPKCS12File).getEncoded(ASN1Encoding.DER);
    }

    public static byte[] convertToDefiniteLength(byte[] berPKCS12File, char[] passwd, String provider) throws IOException {
        Pfx pfx = Pfx.getInstance(berPKCS12File);
        ContentInfo info = pfx.getAuthSafe();
        ContentInfo info2 = new ContentInfo(info.getContentType(), new DEROctetString(ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(info.getContent()).getOctets()).getEncoded(ASN1Encoding.DER)));
        MacData mData = pfx.getMacData();
        try {
            int itCount = mData.getIterationCount().intValue();
            return new Pfx(info2, new MacData(new DigestInfo(new AlgorithmIdentifier(mData.getMac().getAlgorithmId().getAlgorithm(), DERNull.INSTANCE), calculatePbeMac(mData.getMac().getAlgorithmId().getAlgorithm(), mData.getSalt(), itCount, passwd, ASN1OctetString.getInstance(info2.getContent()).getOctets(), provider)), mData.getSalt(), itCount)).getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            throw new IOException("error constructing MAC: " + e.toString());
        }
    }

    private static byte[] calculatePbeMac(ASN1ObjectIdentifier oid, byte[] salt, int itCount, char[] password, byte[] data, String provider) throws Exception {
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance(oid.getId(), provider);
        PBEParameterSpec defParams = new PBEParameterSpec(salt, itCount);
        SecretKey key = keyFact.generateSecret(new PBEKeySpec(password));
        Mac mac = Mac.getInstance(oid.getId(), provider);
        mac.init(key, defParams);
        mac.update(data);
        return mac.doFinal();
    }
}
