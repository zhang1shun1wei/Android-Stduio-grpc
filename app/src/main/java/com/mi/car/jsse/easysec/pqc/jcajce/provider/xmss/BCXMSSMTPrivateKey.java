package com.mi.car.jsse.easysec.pqc.jcajce.provider.xmss;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.asn1.XMSSMTKeyParams;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSMTPrivateKey;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

public class BCXMSSMTPrivateKey implements PrivateKey, XMSSMTPrivateKey {
    private static final long serialVersionUID = 7682140473044521395L;
    private transient ASN1Set attributes;
    private transient XMSSMTPrivateKeyParameters keyParams;
    private transient ASN1ObjectIdentifier treeDigest;

    public BCXMSSMTPrivateKey(ASN1ObjectIdentifier treeDigest2, XMSSMTPrivateKeyParameters keyParams2) {
        this.treeDigest = treeDigest2;
        this.keyParams = keyParams2;
    }

    public BCXMSSMTPrivateKey(PrivateKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo) throws IOException {
        this.attributes = keyInfo.getAttributes();
        this.treeDigest = XMSSMTKeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters()).getTreeDigest().getAlgorithm();
        this.keyParams = (XMSSMTPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSMTPrivateKey
    public long getIndex() {
        if (getUsagesRemaining() != 0) {
            return this.keyParams.getIndex();
        }
        throw new IllegalStateException("key exhausted");
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSMTPrivateKey
    public long getUsagesRemaining() {
        return this.keyParams.getUsagesRemaining();
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.XMSSMTPrivateKey
    public XMSSMTPrivateKey extractKeyShard(int usageCount) {
        return new BCXMSSMTPrivateKey(this.treeDigest, this.keyParams.extractKeyShard(usageCount));
    }

    public String getAlgorithm() {
        return "XMSSMT";
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

    /* access modifiers changed from: package-private */
    public CipherParameters getKeyParams() {
        return this.keyParams;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof BCXMSSMTPrivateKey)) {
            return false;
        }
        BCXMSSMTPrivateKey otherKey = (BCXMSSMTPrivateKey) o;
        return this.treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(this.keyParams.toByteArray(), otherKey.keyParams.toByteArray());
    }

    public int hashCode() {
        return this.treeDigest.hashCode() + (Arrays.hashCode(this.keyParams.toByteArray()) * 37);
    }

    /* access modifiers changed from: package-private */
    public ASN1ObjectIdentifier getTreeDigestOID() {
        return this.treeDigest;
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
        init(PrivateKeyInfo.getInstance((byte[]) in.readObject()));
    }

    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();
        out.writeObject(getEncoded());
    }
}
