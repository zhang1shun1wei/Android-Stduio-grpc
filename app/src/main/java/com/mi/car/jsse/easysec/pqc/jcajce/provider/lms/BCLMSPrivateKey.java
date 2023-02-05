package com.mi.car.jsse.easysec.pqc.jcajce.provider.lms;

import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.HSSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.lms.LMSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.LMSPrivateKey;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

public class BCLMSPrivateKey implements PrivateKey, LMSPrivateKey {
    private static final long serialVersionUID = 8568701712864512338L;
    private transient ASN1Set attributes;
    private transient LMSKeyParameters keyParams;

    public BCLMSPrivateKey(LMSKeyParameters keyParams2) {
        this.keyParams = keyParams2;
    }

    public BCLMSPrivateKey(PrivateKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo) throws IOException {
        this.attributes = keyInfo.getAttributes();
        this.keyParams = (LMSKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.LMSPrivateKey
    public long getIndex() {
        if (getUsagesRemaining() == 0) {
            throw new IllegalStateException("key exhausted");
        } else if (this.keyParams instanceof LMSPrivateKeyParameters) {
            return (long) ((LMSPrivateKeyParameters) this.keyParams).getIndex();
        } else {
            return ((HSSPrivateKeyParameters) this.keyParams).getIndex();
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.LMSPrivateKey
    public long getUsagesRemaining() {
        if (this.keyParams instanceof LMSPrivateKeyParameters) {
            return ((LMSPrivateKeyParameters) this.keyParams).getUsagesRemaining();
        }
        return ((HSSPrivateKeyParameters) this.keyParams).getUsagesRemaining();
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.LMSPrivateKey
    public LMSPrivateKey extractKeyShard(int usageCount) {
        if (this.keyParams instanceof LMSPrivateKeyParameters) {
            return new BCLMSPrivateKey(((LMSPrivateKeyParameters) this.keyParams).extractKeyShard(usageCount));
        }
        return new BCLMSPrivateKey(((HSSPrivateKeyParameters) this.keyParams).extractKeyShard(usageCount));
    }

    public String getAlgorithm() {
        return "LMS";
    }

    public String getFormat() {
        return "PKCS#8";
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
        if (!(o instanceof BCLMSPrivateKey)) {
            return false;
        }
        try {
            return Arrays.areEqual(this.keyParams.getEncoded(), ((BCLMSPrivateKey) o).keyParams.getEncoded());
        } catch (IOException e) {
            throw new IllegalStateException("unable to perform equals");
        }
    }

    public int hashCode() {
        try {
            return Arrays.hashCode(this.keyParams.getEncoded());
        } catch (IOException e) {
            throw new IllegalStateException("unable to calculate hashCode");
        }
    }

    /* access modifiers changed from: package-private */
    public CipherParameters getKeyParams() {
        return this.keyParams;
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.LMSKey
    public int getLevels() {
        if (this.keyParams instanceof LMSPrivateKeyParameters) {
            return 1;
        }
        return ((HSSPrivateKeyParameters) this.keyParams).getL();
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
