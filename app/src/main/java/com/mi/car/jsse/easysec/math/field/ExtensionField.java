package com.mi.car.jsse.easysec.math.field;

public interface ExtensionField extends FiniteField {
    int getDegree();

    FiniteField getSubfield();
}
