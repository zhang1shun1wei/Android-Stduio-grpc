package com.mi.car.jsse.easysec.pqc.jcajce.provider.saber;

import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.pqc.crypto.saber.SABERPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.SABERKey;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.SABERParameterSpec;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

public class BCSABERPrivateKey implements PrivateKey, SABERKey {
    private static final long serialVersionUID = 1;
    private transient ASN1Set attributes;
    private transient SABERPrivateKeyParameters params;

    public BCSABERPrivateKey(SABERPrivateKeyParameters params2) {
        this.params = params2;
    }

    public BCSABERPrivateKey(PrivateKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo) throws IOException {
        this.attributes = keyInfo.getAttributes();
        this.params = (SABERPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof BCSABERPrivateKey) {
            return Arrays.areEqual(this.params.getEncoded(), ((BCSABERPrivateKey) o).params.getEncoded());
        }
        return false;
    }

    public int hashCode() {
        return Arrays.hashCode(this.params.getEncoded());
    }

    public final String getAlgorithm() {
        return "SABER";
    }

    public byte[] getEncoded() {
        try {
            return PrivateKeyInfoFactory.createPrivateKeyInfo(this.params, this.attributes).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.SABERKey
    public SABERParameterSpec getParameterSpec() {
        return SABERParameterSpec.fromName(this.params.getParameters().getName());
    }

    public String getFormat() {
        return "PKCS#8";
    }

    /* access modifiers changed from: package-private */
    public SABERPrivateKeyParameters getKeyParams() {
        return this.params;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        init(PrivateKeyInfo.getInstance((byte[]) in.readObject()));
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeObject(getEncoded());
    }
}
