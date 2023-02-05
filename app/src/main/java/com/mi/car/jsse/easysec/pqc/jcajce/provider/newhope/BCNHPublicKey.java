package com.mi.car.jsse.easysec.pqc.jcajce.provider.newhope;

import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.crypto.newhope.NHPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.NHPublicKey;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class BCNHPublicKey implements NHPublicKey {
    private static final long serialVersionUID = 1;
    private transient NHPublicKeyParameters params;

    public BCNHPublicKey(NHPublicKeyParameters params2) {
        this.params = params2;
    }

    public BCNHPublicKey(SubjectPublicKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo) throws IOException {
        this.params = (NHPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o) {
        if (o == null || !(o instanceof BCNHPublicKey)) {
            return false;
        }
        return Arrays.areEqual(this.params.getPubData(), ((BCNHPublicKey) o).params.getPubData());
    }

    public int hashCode() {
        return Arrays.hashCode(this.params.getPubData());
    }

    public final String getAlgorithm() {
        return "NH";
    }

    public byte[] getEncoded() {
        try {
            return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(this.params).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    public String getFormat() {
        return "X.509";
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.NHPublicKey
    public byte[] getPublicData() {
        return this.params.getPubData();
    }

    /* access modifiers changed from: package-private */
    public CipherParameters getKeyParams() {
        return this.params;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        init(SubjectPublicKeyInfo.getInstance((byte[]) in.readObject()));
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeObject(getEncoded());
    }
}
