package com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSKey;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class BCXMSSPublicKey implements PublicKey, XMSSKey {
    private static final long serialVersionUID = -5617456225328969766L;
    private transient XMSSPublicKeyParameters keyParams;
    private transient ASN1ObjectIdentifier treeDigest;

    public BCXMSSPublicKey(ASN1ObjectIdentifier treeDigest2, XMSSPublicKeyParameters keyParams2) {
        this.treeDigest = treeDigest2;
        this.keyParams = keyParams2;
    }

    public BCXMSSPublicKey(SubjectPublicKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo) throws IOException {
        this.keyParams = (XMSSPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
        this.treeDigest = DigestUtil.getDigestOID(this.keyParams.getTreeDigest());
    }

    public final String getAlgorithm() {
        return "XMSS";
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
        if (!(o instanceof BCXMSSPublicKey)) {
            return false;
        }
        BCXMSSPublicKey otherKey = (BCXMSSPublicKey) o;
        try {
            return this.treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(this.keyParams.getEncoded(), otherKey.keyParams.getEncoded());
        } catch (IOException e) {
            return false;
        }
    }

    public int hashCode() {
        try {
            return this.treeDigest.hashCode() + (Arrays.hashCode(this.keyParams.getEncoded()) * 37);
        } catch (IOException e) {
            return this.treeDigest.hashCode();
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSKey
    public int getHeight() {
        return this.keyParams.getParameters().getHeight();
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSKey
    public String getTreeDigest() {
        return DigestUtil.getXMSSDigestName(this.treeDigest);
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
