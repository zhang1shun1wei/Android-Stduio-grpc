package com.mi.car.jsse.easysec.oer;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.oer.OERDefinition;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class Element {
    private final Switch aSwitch;
    private final OERDefinition.BaseType baseType;
    private final int block;
    private final List<Element> children;
    private final ASN1Encodable defaultValue;
    private final boolean defaultValuesInChildren;
    private final ElementSupplier elementSupplier;
    private final BigInteger enumValue;
    private final boolean explicit;
    private final boolean extensionsInDefinition;
    private final String label;
    private final BigInteger lowerBound;
    private final boolean mayRecurse;
    private List<Element> optionalChildrenInOrder;
    private final int optionals;
    private Element parent;
    private final Map<String, ElementSupplier> supplierMap;
    private final String typeName;
    private final BigInteger upperBound;
    private List<ASN1Encodable> validSwitchValues;

    public Element(OERDefinition.BaseType baseType2, List<Element> children2, boolean explicit2, String label2, BigInteger lowerBound2, BigInteger upperBound2, boolean extensionsInDefinition2, BigInteger enumValue2, ASN1Encodable defaultValue2, Switch aSwitch2, List<ASN1Encodable> switchValues, ElementSupplier elementSupplier2, boolean mayRecurse2, String typeName2, Map<String, ElementSupplier> supplierMap2, int block2, int optionals2, boolean defaultValuesInChildren2) {
        this.baseType = baseType2;
        this.children = children2;
        this.explicit = explicit2;
        this.label = label2;
        this.lowerBound = lowerBound2;
        this.upperBound = upperBound2;
        this.extensionsInDefinition = extensionsInDefinition2;
        this.enumValue = enumValue2;
        this.defaultValue = defaultValue2;
        this.aSwitch = aSwitch2;
        this.validSwitchValues = switchValues != null ? Collections.unmodifiableList(switchValues) : null;
        this.elementSupplier = elementSupplier2;
        this.mayRecurse = mayRecurse2;
        this.typeName = typeName2;
        this.block = block2;
        this.optionals = optionals2;
        this.defaultValuesInChildren = defaultValuesInChildren2;
        if (supplierMap2 == null) {
            this.supplierMap = Collections.emptyMap();
        } else {
            this.supplierMap = supplierMap2;
        }
        for (Element e : children2) {
            e.parent = this;
        }
    }

    public Element(Element element, Element parent2) {
        this.baseType = element.baseType;
        this.children = new ArrayList(element.children);
        this.explicit = element.explicit;
        this.label = element.label;
        this.lowerBound = element.lowerBound;
        this.upperBound = element.upperBound;
        this.extensionsInDefinition = element.extensionsInDefinition;
        this.enumValue = element.enumValue;
        this.defaultValue = element.defaultValue;
        this.aSwitch = element.aSwitch;
        this.validSwitchValues = element.validSwitchValues;
        this.elementSupplier = element.elementSupplier;
        this.mayRecurse = element.mayRecurse;
        this.typeName = element.typeName;
        this.supplierMap = element.supplierMap;
        this.parent = parent2;
        this.block = element.block;
        this.optionals = element.optionals;
        this.defaultValuesInChildren = element.defaultValuesInChildren;
        for (Element e : this.children) {
            e.parent = this;
        }
    }

    public static Element expandDeferredDefinition(Element e, Element parent2) {
        if (e.elementSupplier == null) {
            return e;
        }
        Element e2 = e.elementSupplier.build();
        if (e2.getParent() != parent2) {
            return new Element(e2, parent2);
        }
        return e2;
    }

    public String rangeExpression() {
        return "(" + (getLowerBound() != null ? getLowerBound().toString() : "MIN") + " ... " + (getUpperBound() != null ? getUpperBound().toString() : "MAX") + ")";
    }

    public String appendLabel(String s) {
        return "[" + (getLabel() == null ? "" : getLabel()) + (isExplicit() ? " (E)" : "") + "] " + s;
    }

    public List<Element> optionalOrDefaultChildrenInOrder() {
        List<Element> optionalChildrenInOrder2;
        synchronized (this) {
            if (getOptionalChildrenInOrder() == null) {
                ArrayList<Element> optList = new ArrayList<>();
                for (Element e : getChildren()) {
                    if (!e.isExplicit() || e.getDefaultValue() != null) {
                        optList.add(e);
                    }
                }
                this.optionalChildrenInOrder = Collections.unmodifiableList(optList);
            }
            optionalChildrenInOrder2 = getOptionalChildrenInOrder();
        }
        return optionalChildrenInOrder2;
    }

    public boolean isUnbounded() {
        return getUpperBound() == null && getLowerBound() == null;
    }

    public boolean isLowerRangeZero() {
        return BigInteger.ZERO.equals(getLowerBound());
    }

    public boolean isUnsignedWithRange() {
        return isLowerRangeZero() && getUpperBound() != null && BigInteger.ZERO.compareTo(getUpperBound()) < 0;
    }

    public boolean canBeNegative() {
        return getLowerBound() != null && BigInteger.ZERO.compareTo(getLowerBound()) > 0;
    }

    public int intBytesForRange() {
        if (!(getLowerBound() == null || getUpperBound() == null)) {
            if (BigInteger.ZERO.equals(getLowerBound())) {
                int i = 0;
                int j = 1;
                while (i < OERDefinition.uIntMax.length) {
                    if (getUpperBound().compareTo(OERDefinition.uIntMax[i]) < 0) {
                        return j;
                    }
                    i++;
                    j *= 2;
                }
            } else {
                int i2 = 0;
                int j2 = 1;
                while (i2 < OERDefinition.sIntRange.length) {
                    if (getLowerBound().compareTo(OERDefinition.sIntRange[i2][0]) >= 0 && getUpperBound().compareTo(OERDefinition.sIntRange[i2][1]) < 0) {
                        return -j2;
                    }
                    i2++;
                    j2 *= 2;
                }
            }
        }
        return 0;
    }

    public boolean hasPopulatedExtension() {
        return this.extensionsInDefinition;
    }

    public boolean hasDefaultChildren() {
        return this.defaultValuesInChildren;
    }

    public ASN1Encodable getDefaultValue() {
        return this.defaultValue;
    }

    public Element getFirstChid() {
        return getChildren().get(0);
    }

    public boolean isFixedLength() {
        return getLowerBound() != null && getLowerBound().equals(getUpperBound());
    }

    public String toString() {
        return "[" + this.typeName + " " + this.baseType.name() + " '" + getLabel() + "']";
    }

    public OERDefinition.BaseType getBaseType() {
        return this.baseType;
    }

    public List<Element> getChildren() {
        return this.children;
    }

    public boolean isExplicit() {
        return this.explicit;
    }

    public String getLabel() {
        return this.label;
    }

    public BigInteger getLowerBound() {
        return this.lowerBound;
    }

    public BigInteger getUpperBound() {
        return this.upperBound;
    }

    public boolean isExtensionsInDefinition() {
        return this.extensionsInDefinition;
    }

    public BigInteger getEnumValue() {
        return this.enumValue;
    }

    public Switch getaSwitch() {
        return this.aSwitch;
    }

    public List<Element> getOptionalChildrenInOrder() {
        return this.optionalChildrenInOrder;
    }

    public List<ASN1Encodable> getValidSwitchValues() {
        return this.validSwitchValues;
    }

    public ElementSupplier getElementSupplier() {
        return this.elementSupplier;
    }

    public boolean isMayRecurse() {
        return this.mayRecurse;
    }

    public String getTypeName() {
        return this.typeName;
    }

    public int getOptionals() {
        return this.optionals;
    }

    public int getBlock() {
        return this.block;
    }

    public String getDerivedTypeName() {
        if (this.typeName != null) {
            return this.typeName;
        }
        return this.baseType.name();
    }

    public ElementSupplier resolveSupplier() {
        if (this.supplierMap.containsKey(this.label)) {
            return this.supplierMap.get(this.label);
        }
        if (this.parent != null) {
            return this.parent.resolveSupplier(this.label);
        }
        throw new IllegalStateException("unable to resolve: " + this.label);
    }

    /* access modifiers changed from: protected */
    public ElementSupplier resolveSupplier(String name) {
        String name2 = this.label + "." + name;
        if (this.supplierMap.containsKey(name2)) {
            return this.supplierMap.get(name2);
        }
        if (this.parent != null) {
            return this.parent.resolveSupplier(name2);
        }
        throw new IllegalStateException("unable to resolve: " + name2);
    }

    public Element getParent() {
        return this.parent;
    }

    public boolean equals(Object o) {
        boolean z = true;
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Element element = (Element) o;
        if (this.explicit != element.explicit || this.extensionsInDefinition != element.extensionsInDefinition || this.defaultValuesInChildren != element.defaultValuesInChildren || this.mayRecurse != element.mayRecurse || this.optionals != element.optionals || this.block != element.block || this.baseType != element.baseType) {
            return false;
        }
        if (this.children != null) {
            if (!this.children.equals(element.children)) {
                return false;
            }
        } else if (element.children != null) {
            return false;
        }
        if (this.label != null) {
            if (!this.label.equals(element.label)) {
                return false;
            }
        } else if (element.label != null) {
            return false;
        }
        if (this.lowerBound != null) {
            if (!this.lowerBound.equals(element.lowerBound)) {
                return false;
            }
        } else if (element.lowerBound != null) {
            return false;
        }
        if (this.upperBound != null) {
            if (!this.upperBound.equals(element.upperBound)) {
                return false;
            }
        } else if (element.upperBound != null) {
            return false;
        }
        if (this.enumValue != null) {
            if (!this.enumValue.equals(element.enumValue)) {
                return false;
            }
        } else if (element.enumValue != null) {
            return false;
        }
        if (this.defaultValue != null) {
            if (!this.defaultValue.equals(element.defaultValue)) {
                return false;
            }
        } else if (element.defaultValue != null) {
            return false;
        }
        if (this.aSwitch != null) {
            if (!this.aSwitch.equals(element.aSwitch)) {
                return false;
            }
        } else if (element.aSwitch != null) {
            return false;
        }
        if (this.optionalChildrenInOrder != null) {
            if (!this.optionalChildrenInOrder.equals(element.optionalChildrenInOrder)) {
                return false;
            }
        } else if (element.optionalChildrenInOrder != null) {
            return false;
        }
        if (this.validSwitchValues != null) {
            if (!this.validSwitchValues.equals(element.validSwitchValues)) {
                return false;
            }
        } else if (element.validSwitchValues != null) {
            return false;
        }
        if (this.elementSupplier != null) {
            if (!this.elementSupplier.equals(element.elementSupplier)) {
                return false;
            }
        } else if (element.elementSupplier != null) {
            return false;
        }
        if (this.typeName != null) {
            if (!this.typeName.equals(element.typeName)) {
                return false;
            }
        } else if (element.typeName != null) {
            return false;
        }
        if (this.supplierMap != null) {
            if (this.supplierMap.equals(element.supplierMap)) {
                z = false;
            }
        } else if (element.supplierMap == null) {
            z = false;
        }
        return z;
    }

    public int hashCode() {
        int result;
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        int i11;
        int i12;
        int i13;
        int i14;
        int i15 = 1;
        int i16 = 0;
        if (this.baseType != null) {
            result = this.baseType.hashCode();
        } else {
            result = 0;
        }
        int i17 = result * 31;
        if (this.children != null) {
            i = this.children.hashCode();
        } else {
            i = 0;
        }
        int i18 = (i17 + i) * 31;
        if (this.explicit) {
            i2 = 1;
        } else {
            i2 = 0;
        }
        int i19 = (i18 + i2) * 31;
        if (this.label != null) {
            i3 = this.label.hashCode();
        } else {
            i3 = 0;
        }
        int i20 = (i19 + i3) * 31;
        if (this.lowerBound != null) {
            i4 = this.lowerBound.hashCode();
        } else {
            i4 = 0;
        }
        int i21 = (i20 + i4) * 31;
        if (this.upperBound != null) {
            i5 = this.upperBound.hashCode();
        } else {
            i5 = 0;
        }
        int i22 = (i21 + i5) * 31;
        if (this.extensionsInDefinition) {
            i6 = 1;
        } else {
            i6 = 0;
        }
        int i23 = (i22 + i6) * 31;
        if (this.enumValue != null) {
            i7 = this.enumValue.hashCode();
        } else {
            i7 = 0;
        }
        int i24 = (i23 + i7) * 31;
        if (this.defaultValue != null) {
            i8 = this.defaultValue.hashCode();
        } else {
            i8 = 0;
        }
        int i25 = (i24 + i8) * 31;
        if (this.aSwitch != null) {
            i9 = this.aSwitch.hashCode();
        } else {
            i9 = 0;
        }
        int i26 = (i25 + i9) * 31;
        if (this.defaultValuesInChildren) {
            i10 = 1;
        } else {
            i10 = 0;
        }
        int i27 = (i26 + i10) * 31;
        if (this.optionalChildrenInOrder != null) {
            i11 = this.optionalChildrenInOrder.hashCode();
        } else {
            i11 = 0;
        }
        int i28 = (i27 + i11) * 31;
        if (this.validSwitchValues != null) {
            i12 = this.validSwitchValues.hashCode();
        } else {
            i12 = 0;
        }
        int i29 = (i28 + i12) * 31;
        if (this.elementSupplier != null) {
            i13 = this.elementSupplier.hashCode();
        } else {
            i13 = 0;
        }
        int i30 = (i29 + i13) * 31;
        if (!this.mayRecurse) {
            i15 = 0;
        }
        int i31 = (i30 + i15) * 31;
        if (this.typeName != null) {
            i14 = this.typeName.hashCode();
        } else {
            i14 = 0;
        }
        int i32 = (i31 + i14) * 31;
        if (this.supplierMap != null) {
            i16 = this.supplierMap.hashCode();
        }
        return ((((i32 + i16) * 31) + this.optionals) * 31) + this.block;
    }
}
