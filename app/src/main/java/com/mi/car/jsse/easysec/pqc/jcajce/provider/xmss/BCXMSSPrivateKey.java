package com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSKeyParams;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSPrivateKey;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

public class BCXMSSPrivateKey implements PrivateKey, XMSSPrivateKey {
    private static final long serialVersionUID = 8568701712864512338L;
    private transient ASN1Set attributes;
    private transient XMSSPrivateKeyParameters keyParams;
    private transient ASN1ObjectIdentifier treeDigest;

    public BCXMSSPrivateKey(ASN1ObjectIdentifier treeDigest2, XMSSPrivateKeyParameters keyParams2) {
        this.treeDigest = treeDigest2;
        this.keyParams = keyParams2;
    }

    public BCXMSSPrivateKey(PrivateKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo) throws IOException {
        this.attributes = keyInfo.getAttributes();
        this.treeDigest = XMSSKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters()).getTreeDigest().getAlgorithm();
        this.keyParams = (XMSSPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSPrivateKey
    public long getIndex() {
        if (getUsagesRemaining() != 0) {
            return (long) this.keyParams.getIndex();
        }
        throw new IllegalStateException("key exhausted");
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSPrivateKey
    public long getUsagesRemaining() {
        return this.keyParams.getUsagesRemaining();
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSPrivateKey
    public XMSSPrivateKey extractKeyShard(int usageCount) {
        return new BCXMSSPrivateKey(this.treeDigest, this.keyParams.extractKeyShard(usageCount));
    }

    public String getAlgorithm() {
        return "XMSS";
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
        if (!(o instanceof BCXMSSPrivateKey)) {
            return false;
        }
        BCXMSSPrivateKey otherKey = (BCXMSSPrivateKey) o;
        return this.treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(this.keyParams.toByteArray(), otherKey.keyParams.toByteArray());
    }

    public int hashCode() {
        return this.treeDigest.hashCode() + (Arrays.hashCode(this.keyParams.toByteArray()) * 37);
    }

    /* access modifiers changed from: package-private */
    public CipherParameters getKeyParams() {
        return this.keyParams;
    }

    /* access modifiers changed from: package-private */
    public ASN1ObjectIdentifier getTreeDigestOID() {
        return this.treeDigest;
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
        init(PrivateKeyInfo.getInstance((byte[]) in.readObject()));
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeObject(getEncoded());
    }
}
