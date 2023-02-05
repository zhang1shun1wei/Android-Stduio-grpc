package com.mi.car.jsse.easysec.pqc.jcajce.provider.qtesla;

import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.qtesla.QTESLASecurityCategory;
import com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.QTESLAKey;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.QTESLAParameterSpec;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class BCqTESLAPublicKey implements PublicKey, QTESLAKey {
    private static final long serialVersionUID = 1;
    private transient QTESLAPublicKeyParameters keyParams;

    public BCqTESLAPublicKey(QTESLAPublicKeyParameters keyParams2) {
        this.keyParams = keyParams2;
    }

    public BCqTESLAPublicKey(SubjectPublicKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo) throws IOException {
        this.keyParams = (QTESLAPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    public final String getAlgorithm() {
        return QTESLASecurityCategory.getName(this.keyParams.getSecurityCategory());
    }

    public byte[] getEncoded() {
        try {
            return SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(this.keyParams).getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    public String getFormat() {
        return "X.509";
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.QTESLAKey
    public QTESLAParameterSpec getParams() {
        return new QTESLAParameterSpec(getAlgorithm());
    }

    /* access modifiers changed from: package-private */
    public CipherParameters getKeyParams() {
        return this.keyParams;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof BCqTESLAPublicKey)) {
            return false;
        }
        BCqTESLAPublicKey otherKey = (BCqTESLAPublicKey) o;
        return this.keyParams.getSecurityCategory() == otherKey.keyParams.getSecurityCategory() && Arrays.areEqual(this.keyParams.getPublicData(), otherKey.keyParams.getPublicData());
    }

    public int hashCode() {
        return this.keyParams.getSecurityCategory() + (Arrays.hashCode(this.keyParams.getPublicData()) * 37);
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
