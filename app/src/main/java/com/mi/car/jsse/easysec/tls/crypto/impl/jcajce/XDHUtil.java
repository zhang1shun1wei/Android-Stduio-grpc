package com.mi.car.jsse.easysec.tls.crypto.impl.jcajce;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.jcajce.interfaces.XDHPublicKey;
import com.mi.car.jsse.easysec.jcajce.spec.RawEncodedKeySpec;
import com.mi.car.jsse.easysec.jce.provider.EasysecProvider;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/* access modifiers changed from: package-private */
public class XDHUtil {
    XDHUtil() {
    }

    static PublicKey decodePublicKey(JcaTlsCrypto crypto, String keyFactoryAlgorithm, ASN1ObjectIdentifier algorithmOID, byte[] encoding) throws TlsFatalAlert {
        try {
            KeyFactory kf = crypto.getHelper().createKeyFactory(keyFactoryAlgorithm);
            if (kf.getProvider() instanceof EasysecProvider) {
                try {
                    return kf.generatePublic(new RawEncodedKeySpec(encoding));
                } catch (Exception e) {
                }
            }
            return kf.generatePublic(createX509EncodedKeySpec(algorithmOID, encoding));
        } catch (Exception e2) {
            throw new TlsFatalAlert((short) 47, (Throwable) e2);
        }
    }

    static byte[] encodePublicKey(PublicKey publicKey) throws TlsFatalAlert {
        if (publicKey instanceof XDHPublicKey) {
            return ((XDHPublicKey) publicKey).getUEncoding();
        }
        if (!"X.509".equals(publicKey.getFormat())) {
            throw new TlsFatalAlert((short) 80, "Public key format unrecognized");
        }
        try {
            return SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getPublicKeyData().getOctets();
        } catch (Exception e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }

    private static X509EncodedKeySpec createX509EncodedKeySpec(ASN1ObjectIdentifier oid, byte[] encoding) throws IOException {
        return new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid), encoding).getEncoded("DER"));
    }
}
