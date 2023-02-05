package com.mi.car.jsse.easysec.pqc.jcajce.provider.sphincs;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.asn1.SPHINCS256KeyParams;
import com.mi.car.jsse.easysec.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.crypto.util.PublicKeyFactory;
import com.mi.car.jsse.easysec.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.mi.car.jsse.easysec.pqc.jcajce.interfaces.SPHINCSKey;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class BCSphincs256PublicKey implements PublicKey, SPHINCSKey {
    private static final long serialVersionUID = 1;
    private transient SPHINCSPublicKeyParameters params;
    private transient ASN1ObjectIdentifier treeDigest;

    public BCSphincs256PublicKey(ASN1ObjectIdentifier treeDigest2, SPHINCSPublicKeyParameters params2) {
        this.treeDigest = treeDigest2;
        this.params = params2;
    }

    public BCSphincs256PublicKey(SubjectPublicKeyInfo keyInfo) throws IOException {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo) throws IOException {
        this.treeDigest = SPHINCS256KeyParams.getInstance(keyInfo.getAlgorithm().getParameters()).getTreeDigest().getAlgorithm();
        this.params = (SPHINCSPublicKeyParameters) PublicKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof BCSphincs256PublicKey)) {
            return false;
        }
        BCSphincs256PublicKey otherKey = (BCSphincs256PublicKey) o;
        return this.treeDigest.equals(otherKey.treeDigest) && Arrays.areEqual(this.params.getKeyData(), otherKey.params.getKeyData());
    }

    public int hashCode() {
        return this.treeDigest.hashCode() + (Arrays.hashCode(this.params.getKeyData()) * 37);
    }

    public final String getAlgorithm() {
        return "SPHINCS-256";
    }

    public byte[] getEncoded() {
        SubjectPublicKeyInfo pki;
        try {
            if (this.params.getTreeDigest() != null) {
                pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(this.params);
            } else {
                pki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256, new SPHINCS256KeyParams(new AlgorithmIdentifier(this.treeDigest))), this.params.getKeyData());
            }
            return pki.getEncoded();
        } catch (IOException e) {
            return null;
        }
    }

    public String getFormat() {
        return "X.509";
    }

    @Override // com.mi.car.jsse.easysec.pqc.jcajce.interfaces.SPHINCSKey
    public byte[] getKeyData() {
        return this.params.getKeyData();
    }

    /* access modifiers changed from: package-private */
    public ASN1ObjectIdentifier getTreeDigest() {
        return this.treeDigest;
    }

    /* access modifiers changed from: package-private */
    public CipherParameters getKeyParams() {
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
