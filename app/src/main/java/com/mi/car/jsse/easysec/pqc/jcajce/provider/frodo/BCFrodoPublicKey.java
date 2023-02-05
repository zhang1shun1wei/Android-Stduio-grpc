package com.mi.car.jsse.easysec.pqc.jcajce.provider.frodo;

import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.FrodoKey;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.FrodoParameterSpec;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class BCFrodoPublicKey implements PublicKey, FrodoKey {
    private static final long serialVersionUID = 1;
    private transient FrodoPublicKeyParameters params;

    public BCFrodoPublicKey(FrodoPublicKeyParameters params2) {
        this.params = params2;
    }

    public BCFrodoPublicKey(SubjectPublicKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo) throws IOException {
        this.params = (FrodoPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof BCFrodoPublicKey) {
            return Arrays.areEqual(this.params.getEncoded(), ((BCFrodoPublicKey) o).params.getEncoded());
        }
        return false;
    }

    public int hashCode() {
        return Arrays.hashCode(this.params.getEncoded());
    }

    public final String getAlgorithm() {
        return "Frodo";
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

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.FrodoKey
    public FrodoParameterSpec getParameterSpec() {
        return FrodoParameterSpec.fromName(this.params.getParameters().getName());
    }

    /* access modifiers changed from: package-private */
    public FrodoPublicKeyParameters getKeyParams() {
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
