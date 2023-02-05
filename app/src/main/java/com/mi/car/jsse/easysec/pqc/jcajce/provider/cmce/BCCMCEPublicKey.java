package com.mi.car.jsse.easysec.pqc.jcajce.provider.cmce;

import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.pqc.crypto.cmce.CMCEPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.CMCEKey;
import com.mi.car.jsse.easysec.pqc.jcajce.spec.CMCEParameterSpec;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class BCCMCEPublicKey implements PublicKey, CMCEKey {
    private static final long serialVersionUID = 1;
    private transient CMCEPublicKeyParameters params;

    public BCCMCEPublicKey(CMCEPublicKeyParameters params2) {
        this.params = params2;
    }

    public BCCMCEPublicKey(SubjectPublicKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo) throws IOException {
        this.params = (CMCEPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof BCCMCEPublicKey) {
            return Arrays.areEqual(this.params.getEncoded(), ((BCCMCEPublicKey) o).params.getEncoded());
        }
        return false;
    }

    public int hashCode() {
        return Arrays.hashCode(this.params.getEncoded());
    }

    public final String getAlgorithm() {
        return "CMCE";
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

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.CMCEKey
    public CMCEParameterSpec getParameterSpec() {
        return CMCEParameterSpec.fromName(this.params.getParameters().getName());
    }

    /* access modifiers changed from: package-private */
    public CMCEPublicKeyParameters getKeyParams() {
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
