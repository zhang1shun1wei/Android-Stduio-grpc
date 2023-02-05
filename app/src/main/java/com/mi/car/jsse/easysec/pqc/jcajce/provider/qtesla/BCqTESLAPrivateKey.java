package com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla;

import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLASecurityCategory;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.QTESLAKey;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.QTESLAParameterSpec;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

public class BCqTESLAPrivateKey implements PrivateKey, QTESLAKey {
    private static final long serialVersionUID = 1;
    private transient ASN1Set attributes;
    private transient QTESLAPrivateKeyParameters keyParams;

    public BCqTESLAPrivateKey(QTESLAPrivateKeyParameters keyParams2) {
        this.keyParams = keyParams2;
    }

    public BCqTESLAPrivateKey(PrivateKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo) throws IOException {
        this.attributes = keyInfo.getAttributes();
        this.keyParams = (QTESLAPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    public final String getAlgorithm() {
        return QTESLASecurityCategory.getName(this.keyParams.getSecurityCategory());
    }

    public String getFormat() {
        return "PKCS#8";
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.QTESLAKey
    public QTESLAParameterSpec getParams() {
        return new QTESLAParameterSpec(getAlgorithm());
    }

    public byte[] getEncoded() {
        try {
            return PrivateKeyInfoFactory.createPrivateKeyInfo(this.keyParams, this.attributes).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof BCqTESLAPrivateKey)) {
            return false;
        }
        BCqTESLAPrivateKey otherKey = (BCqTESLAPrivateKey) o;
        return this.keyParams.getSecurityCategory() == otherKey.keyParams.getSecurityCategory() && Arrays.areEqual(this.keyParams.getSecret(), otherKey.keyParams.getSecret());
    }

    public int hashCode() {
        return this.keyParams.getSecurityCategory() + (Arrays.hashCode(this.keyParams.getSecret()) * 37);
    }

    /* access modifiers changed from: package-private */
    public CipherParameters getKeyParams() {
        return this.keyParams;
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
