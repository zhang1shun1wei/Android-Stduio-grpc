//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.jcajce;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.misc.MiscObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CompositePublicKey implements PublicKey {
    private final List<PublicKey> keys;

    public CompositePublicKey(PublicKey... keys) {
        if (keys != null && keys.length != 0) {
            List<PublicKey> keyList = new ArrayList(keys.length);

            for(int i = 0; i != keys.length; ++i) {
                keyList.add(keys[i]);
            }

            this.keys = Collections.unmodifiableList(keyList);
        } else {
            throw new IllegalArgumentException("at least one public key must be provided");
        }
    }

    public List<PublicKey> getPublicKeys() {
        return this.keys;
    }

    public String getAlgorithm() {
        return "Composite";
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] getEncoded() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for(int i = 0; i != this.keys.size(); ++i) {
            v.add(SubjectPublicKeyInfo.getInstance(((PublicKey)this.keys.get(i)).getEncoded()));
        }

        try {
            return (new SubjectPublicKeyInfo(new AlgorithmIdentifier(MiscObjectIdentifiers.id_alg_composite), new DERSequence(v))).getEncoded("DER");
        } catch (IOException var3) {
            throw new IllegalStateException("unable to encode composite key: " + var3.getMessage());
        }
    }

    public int hashCode() {
        return this.keys.hashCode();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        } else {
            return o instanceof CompositePublicKey ? this.keys.equals(((CompositePublicKey)o).keys) : false;
        }
    }
}
