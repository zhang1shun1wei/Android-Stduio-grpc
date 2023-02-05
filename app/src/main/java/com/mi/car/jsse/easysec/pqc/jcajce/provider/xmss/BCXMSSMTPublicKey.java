package com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSMTKey;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class BCXMSSMTPublicKey implements PublicKey, XMSSMTKey {
    private static final long serialVersionUID = 3230324130542413475L;
    private transient XMSSMTPublicKeyParameters keyParams;
    private transient ASN1ObjectIdentifier treeDigest;

    public BCXMSSMTPublicKey(ASN1ObjectIdentifier treeDigest2, XMSSMTPublicKeyParameters keyParams2) {
        this.treeDigest = treeDigest2;
        this.keyParams = keyParams2;
    }

    public BCXMSSMTPublicKey(SubjectPublicKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo) throws IOException {
        this.keyParams = (XMSSMTPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
        this.treeDigest = DigestUtil.getDigestOID(this.keyParams.getTreeDigest());
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof BCXMSSMTPublicKey)) {
            return false;
        }
        BCXMSSMTPublicKey otherKey = (BCXMSSMTPublicKey) o;
        return this.treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(this.keyParams.toByteArray(), otherKey.keyParams.toByteArray());
    }

    public int hashCode() {
        return this.treeDigest.hashCode() + (Arrays.hashCode(this.keyParams.toByteArray()) * 37);
    }

    public final String getAlgorithm() {
        return "XMSSMT";
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

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSMTKey
    public int getHeight() {
        return this.keyParams.getParameters().getHeight();
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSMTKey
    public int getLayers() {
        return this.keyParams.getParameters().getLayers();
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSMTKey
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
