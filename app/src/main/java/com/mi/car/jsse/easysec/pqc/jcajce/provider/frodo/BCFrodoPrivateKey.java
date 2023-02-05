package com.mi.car.jsse.easysec.pqc.jcajce.provider.frodo;

import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.FrodoKey;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.FrodoParameterSpec;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

public class BCFrodoPrivateKey implements PrivateKey, FrodoKey {
    private static final long serialVersionUID = 1;
    private transient ASN1Set attributes;
    private transient FrodoPrivateKeyParameters params;

    public BCFrodoPrivateKey(FrodoPrivateKeyParameters params2) {
        this.params = params2;
    }

    public BCFrodoPrivateKey(PrivateKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo) throws IOException {
        this.attributes = keyInfo.getAttributes();
        this.params = (FrodoPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof BCFrodoPrivateKey) {
            return Arrays.areEqual(this.params.getEncoded(), ((BCFrodoPrivateKey) o).params.getEncoded());
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
            return PrivateKeyInfoFactory.createPrivateKeyInfo(this.params, this.attributes).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.FrodoKey
    public FrodoParameterSpec getParameterSpec() {
        return FrodoParameterSpec.fromName(this.params.getParameters().getName());
    }

    public String getFormat() {
        return "PKCS#8";
    }

    /* access modifiers changed from: package-private */
    public FrodoPrivateKeyParameters getKeyParams() {
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
