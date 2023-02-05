package com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincs;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.pkcs.PrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.asn1.SPHINCS256KeyParams;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.PrivateKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.SPHINCSKey;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

public class BCSphincs256PrivateKey implements PrivateKey, SPHINCSKey {
    private static final long serialVersionUID = 1;
    private transient ASN1Set attributes;
    private transient SPHINCSPrivateKeyParameters params;
    private transient ASN1ObjectIdentifier treeDigest;

    public BCSphincs256PrivateKey(ASN1ObjectIdentifier treeDigest2, SPHINCSPrivateKeyParameters params2) {
        this.treeDigest = treeDigest2;
        this.params = params2;
    }

    public BCSphincs256PrivateKey(PrivateKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo) throws IOException {
        this.attributes = keyInfo.getAttributes();
        this.treeDigest = SPHINCS256KeyParams.getInstance(keyInfo.getPrivateKeyAlgorithm().getParameters()).getTreeDigest().getAlgorithm();
        this.params = (SPHINCSPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof BCSphincs256PrivateKey)) {
            return false;
        }
        BCSphincs256PrivateKey otherKey = (BCSphincs256PrivateKey) o;
        return this.treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(this.params.getKeyData(), otherKey.params.getKeyData());
    }

    public int hashCode() {
        return this.treeDigest.hashCode() + (Arrays.hashCode(this.params.getKeyData()) * 37);
    }

    public final String getAlgorithm() {
        return "SPHINCS-256";
    }

    public byte[] getEncoded() {
        PrivateKeyInfo pki;
        try {
            if (this.params.getTreeDigest() != null) {
                pki = PrivateKeyInfoFactory.createPrivateKeyInfo(this.params, this.attributes);
            } else {
                pki = new PrivateKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256, new SPHINCS256KeyParams(new AlgorithmIdentifier(this.treeDigest))), new DEROctetString(this.params.getKeyData()), this.attributes);
            }
            return pki.getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    public String getFormat() {
        return "PKCS#8";
    }

    /* access modifiers changed from: package-private */
    public ASN1ObjectIdentifier getTreeDigest() {
        return this.treeDigest;
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.SPHINCSKey
    public byte[] getKeyData() {
        return this.params.getKeyData();
    }

    /* access modifiers changed from: package-private */
    public CipherParameters getKeyParams() {
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
