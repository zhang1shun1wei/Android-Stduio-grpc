package com.mi.car.jsse.easysec.pqc.jcajce.provider.newhope;

import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.NHPrivateKey;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class BCNHPrivateKey implements NHPrivateKey {
    private static final long serialVersionUID = 1;
    private transient ASN1Set attributes;
    private transient NHPrivateKeyParameters params;

    public BCNHPrivateKey(NHPrivateKeyParameters params2) {
        this.params = params2;
    }

    public BCNHPrivateKey(PrivateKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo) throws IOException {
        this.attributes = keyInfo.getAttributes();
        this.params = (NHPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o) {
        if (!(o instanceof BCNHPrivateKey)) {
            return false;
        }
        return Arrays.areEqual(this.params.getSecData(), ((BCNHPrivateKey) o).params.getSecData());
    }

    public int hashCode() {
        return Arrays.hashCode(this.params.getSecData());
    }

    public final String getAlgorithm() {
        return "NH";
    }

    public byte[] getEncoded() {
        try {
            return PrivateKeyInfoFactory.createPrivateKeyInfo(this.params, this.attributes).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    public String getFormat() {
        return "PKCS#8";
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.NHPrivateKey
    public short[] getSecretData() {
        return this.params.getSecData();
    }

    /* access modifiers changed from: package-private */
    public CipherParameters getKeyParams() {
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
