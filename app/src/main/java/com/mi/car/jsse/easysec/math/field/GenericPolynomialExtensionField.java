package com.mi.car.jsse.easysec.math.field;

import com.mi.car.jsse.easysec.util.Integers;
import java.math.BigInteger;

/* access modifiers changed from: package-private */
public class GenericPolynomialExtensionField implements PolynomialExtensionField {
    protected final Polynomial minimalPolynomial;
    protected final FiniteField subfield;

    GenericPolynomialExtensionField(FiniteField subfield2, Polynomial polynomial) {
        this.subfield = subfield2;
        this.minimalPolynomial = polynomial;
    }

    @Override // com.mi.car.jsse.easysec.math.field.FiniteField
    public BigInteger getCharacteristic() {
        return this.subfield.getCharacteristic();
    }

    @Override // com.mi.car.jsse.easysec.math.field.FiniteField
    public int getDimension() {
        return this.subfield.getDimension() * this.minimalPolynomial.getDegree();
    }

    @Override // com.mi.car.jsse.easysec.math.field.ExtensionField
    public FiniteField getSubfield() {
        return this.subfield;
    }

    @Override // com.mi.car.jsse.easysec.math.field.ExtensionField
    public int getDegree() {
        return this.minimalPolynomial.getDegree();
    }

    @Override // com.mi.car.jsse.easysec.math.field.PolynomialExtensionField
    public Polynomial getMinimalPolynomial() {
        return this.minimalPolynomial;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GenericPolynomialExtensionField)) {
            return false;
        }
        GenericPolynomialExtensionField other = (GenericPolynomialExtensionField) obj;
        return this.subfield.equals(other.subfield) && this.minimalPolynomial.equals(other.minimalPolynomial);
    }

    public int hashCode() {
        return this.subfield.hashCode() ^ Integers.rotateLeft(this.minimalPolynomial.hashCode(), 16);
    }
}
