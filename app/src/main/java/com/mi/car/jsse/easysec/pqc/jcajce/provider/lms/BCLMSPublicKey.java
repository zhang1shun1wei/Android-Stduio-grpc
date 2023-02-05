package com.mi.car.jsse.easysec.pqc.jcajce.provider.lms;

import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.LMSKey;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class BCLMSPublicKey implements PublicKey, LMSKey {
    private static final long serialVersionUID = -5617456225328969766L;
    private transient LMSKeyParameters keyParams;

    public BCLMSPublicKey(LMSKeyParameters keyParams2) {
        this.keyParams = keyParams2;
    }

    public BCLMSPublicKey(SubjectPublicKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo) throws IOException {
        this.keyParams = (LMSKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    public final String getAlgorithm() {
        return "LMS";
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

    /* access modifiers changed from: package-private */
    public CipherParameters getKeyParams() {
        return this.keyParams;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof BCLMSPublicKey)) {
            return false;
        }
        try {
            return Arrays.areEqual(this.keyParams.getEncoded(), ((BCLMSPublicKey) o).keyParams.getEncoded());
        } catch (IOException e) {
            return false;
        }
    }

    public int hashCode() {
        try {
            return Arrays.hashCode(this.keyParams.getEncoded());
        } catch (IOException e) {
            return -1;
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.LMSKey
    public int getLevels() {
        if (this.keyParams instanceof LMSPublicKeyParameters) {
            return 1;
        }
        return ((HSSPublicKeyParameters) this.keyParams).getL();
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
