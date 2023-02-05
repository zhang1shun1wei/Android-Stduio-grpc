package com.mi.car.jsse.easysec.asn1.eac;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;
import java.util.Enumeration;

public class ECDSAPublicKey extends PublicKeyDataObject {
    private static final int A = 2;
    private static final int B = 4;
    private static final int F = 64;
    private static final int G = 8;
    private static final int P = 1;
    private static final int R = 16;
    private static final int Y = 32;
    private byte[] basePointG;
    private BigInteger cofactorF;
    private BigInteger firstCoefA;
    private int options;
    private BigInteger orderOfBasePointR;
    private BigInteger primeModulusP;
    private byte[] publicPointY;
    private BigInteger secondCoefB;
    private ASN1ObjectIdentifier usage;

    ECDSAPublicKey(ASN1Sequence seq) throws IllegalArgumentException {
        Enumeration en = seq.getObjects();
        this.usage = ASN1ObjectIdentifier.getInstance(en.nextElement());
        this.options = 0;
        while (en.hasMoreElements()) {
            Object obj = en.nextElement();
            if (obj instanceof ASN1TaggedObject) {
                ASN1TaggedObject to = (ASN1TaggedObject) obj;
                switch (to.getTagNo()) {
                    case 1:
                        setPrimeModulusP(UnsignedInteger.getInstance(to).getValue());
                        break;
                    case 2:
                        setFirstCoefA(UnsignedInteger.getInstance(to).getValue());
                        break;
                    case 3:
                        setSecondCoefB(UnsignedInteger.getInstance(to).getValue());
                        break;
                    case 4:
                        setBasePointG(ASN1OctetString.getInstance(to, false));
                        break;
                    case 5:
                        setOrderOfBasePointR(UnsignedInteger.getInstance(to).getValue());
                        break;
                    case 6:
                        setPublicPointY(ASN1OctetString.getInstance(to, false));
                        break;
                    case 7:
                        setCofactorF(UnsignedInteger.getInstance(to).getValue());
                        break;
                    default:
                        this.options = 0;
                        throw new IllegalArgumentException("Unknown Object Identifier!");
                }
            } else {
                throw new IllegalArgumentException("Unknown Object Identifier!");
            }
        }
        if (this.options != 32 && this.options != 127) {
            throw new IllegalArgumentException("All options must be either present or absent!");
        }
    }

    public ECDSAPublicKey(ASN1ObjectIdentifier usage2, byte[] ppY) throws IllegalArgumentException {
        this.usage = usage2;
        setPublicPointY(new DEROctetString(ppY));
    }

    public ECDSAPublicKey(ASN1ObjectIdentifier usage2, BigInteger p, BigInteger a, BigInteger b, byte[] basePoint, BigInteger order, byte[] publicPoint, int cofactor) {
        this.usage = usage2;
        setPrimeModulusP(p);
        setFirstCoefA(a);
        setSecondCoefB(b);
        setBasePointG(new DEROctetString(basePoint));
        setOrderOfBasePointR(order);
        setPublicPointY(new DEROctetString(publicPoint));
        setCofactorF(BigInteger.valueOf((long) cofactor));
    }

    @Override // com.mi.car.jsse.easysec.asn1.eac.PublicKeyDataObject
    public ASN1ObjectIdentifier getUsage() {
        return this.usage;
    }

    public byte[] getBasePointG() {
        if ((this.options & 8) != 0) {
            return Arrays.clone(this.basePointG);
        }
        return null;
    }

    private void setBasePointG(ASN1OctetString basePointG2) throws IllegalArgumentException {
        if ((this.options & 8) == 0) {
            this.options |= 8;
            this.basePointG = basePointG2.getOctets();
            return;
        }
        throw new IllegalArgumentException("Base Point G already set");
    }

    public BigInteger getCofactorF() {
        if ((this.options & 64) != 0) {
            return this.cofactorF;
        }
        return null;
    }

    private void setCofactorF(BigInteger cofactorF2) throws IllegalArgumentException {
        if ((this.options & 64) == 0) {
            this.options |= 64;
            this.cofactorF = cofactorF2;
            return;
        }
        throw new IllegalArgumentException("Cofactor F already set");
    }

    public BigInteger getFirstCoefA() {
        if ((this.options & 2) != 0) {
            return this.firstCoefA;
        }
        return null;
    }

    private void setFirstCoefA(BigInteger firstCoefA2) throws IllegalArgumentException {
        if ((this.options & 2) == 0) {
            this.options |= 2;
            this.firstCoefA = firstCoefA2;
            return;
        }
        throw new IllegalArgumentException("First Coef A already set");
    }

    public BigInteger getOrderOfBasePointR() {
        if ((this.options & 16) != 0) {
            return this.orderOfBasePointR;
        }
        return null;
    }

    private void setOrderOfBasePointR(BigInteger orderOfBasePointR2) throws IllegalArgumentException {
        if ((this.options & 16) == 0) {
            this.options |= 16;
            this.orderOfBasePointR = orderOfBasePointR2;
            return;
        }
        throw new IllegalArgumentException("Order of base point R already set");
    }

    public BigInteger getPrimeModulusP() {
        if ((this.options & 1) != 0) {
            return this.primeModulusP;
        }
        return null;
    }

    private void setPrimeModulusP(BigInteger primeModulusP2) {
        if ((this.options & 1) == 0) {
            this.options |= 1;
            this.primeModulusP = primeModulusP2;
            return;
        }
        throw new IllegalArgumentException("Prime Modulus P already set");
    }

    public byte[] getPublicPointY() {
        if ((this.options & 32) != 0) {
            return Arrays.clone(this.publicPointY);
        }
        return null;
    }

    private void setPublicPointY(ASN1OctetString publicPointY2) throws IllegalArgumentException {
        if ((this.options & 32) == 0) {
            this.options |= 32;
            this.publicPointY = publicPointY2.getOctets();
            return;
        }
        throw new IllegalArgumentException("Public Point Y already set");
    }

    public BigInteger getSecondCoefB() {
        if ((this.options & 4) != 0) {
            return this.secondCoefB;
        }
        return null;
    }

    private void setSecondCoefB(BigInteger secondCoefB2) throws IllegalArgumentException {
        if ((this.options & 4) == 0) {
            this.options |= 4;
            this.secondCoefB = secondCoefB2;
            return;
        }
        throw new IllegalArgumentException("Second Coef B already set");
    }

    public boolean hasParameters() {
        return this.primeModulusP != null;
    }

    public ASN1EncodableVector getASN1EncodableVector(ASN1ObjectIdentifier oid, boolean publicPointOnly) {
        ASN1EncodableVector v = new ASN1EncodableVector(8);
        v.add(oid);
        if (!publicPointOnly) {
            v.add(new UnsignedInteger(1, getPrimeModulusP()));
            v.add(new UnsignedInteger(2, getFirstCoefA()));
            v.add(new UnsignedInteger(3, getSecondCoefB()));
            v.add(new DERTaggedObject(false, 4, new DEROctetString(getBasePointG())));
            v.add(new UnsignedInteger(5, getOrderOfBasePointR()));
        }
        v.add(new DERTaggedObject(false, 6, new DEROctetString(getPublicPointY())));
        if (!publicPointOnly) {
            v.add(new UnsignedInteger(7, getCofactorF()));
        }
        return v;
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(getASN1EncodableVector(this.usage, !hasParameters()));
    }
}
