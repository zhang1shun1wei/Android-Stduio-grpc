package com.mi.car.jsse.easysec.oer;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class OERDefinition {
    static final BigInteger[] uIntMax = new BigInteger[]{new BigInteger("256"), new BigInteger("65536"), new BigInteger("4294967296"), new BigInteger("18446744073709551616")};
    static final BigInteger[][] sIntRange = new BigInteger[][]{{new BigInteger("-128"), new BigInteger("127")}, {new BigInteger("-32768"), new BigInteger("32767")}, {new BigInteger("-2147483648"), new BigInteger("2147483647")}, {new BigInteger("-9223372036854775808"), new BigInteger("9223372036854775807")}};

    public OERDefinition() {
    }

    public static OERDefinition.Builder bool() {
        return new OERDefinition.Builder(OERDefinition.BaseType.BOOLEAN);
    }

    public static OERDefinition.Builder integer() {
        return new OERDefinition.Builder(OERDefinition.BaseType.INT);
    }

    public static OERDefinition.Builder integer(long val) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.INT)).defaultValue(new ASN1Integer(val));
    }

    public static OERDefinition.Builder bitString(long len) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.BIT_STRING)).fixedSize(len);
    }

    public static OERDefinition.Builder integer(BigInteger lower, BigInteger upper) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.INT)).range(lower, upper);
    }

    public static OERDefinition.Builder integer(long lower, long upper) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.INT)).range(BigInteger.valueOf(lower), BigInteger.valueOf(upper));
    }

    public static OERDefinition.Builder integer(long lower, long upper, ASN1Encodable defaultValue) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.INT)).range(lower, upper, defaultValue);
    }

    public static OERDefinition.Builder nullValue() {
        return new OERDefinition.Builder(OERDefinition.BaseType.NULL);
    }

    public static OERDefinition.Builder seq() {
        return new OERDefinition.Builder(OERDefinition.BaseType.SEQ);
    }

    public static OERDefinition.Builder seq(Object... items) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.SEQ)).items(items);
    }

    public static OERDefinition.Builder aSwitch(Switch aSwitch) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.Switch)).decodeSwitch(aSwitch);
    }

    public static OERDefinition.Builder enumItem(String label) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.ENUM_ITEM)).label(label);
    }

    public static OERDefinition.Builder enumItem(String label, BigInteger value) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.ENUM_ITEM)).enumValue(value).label(label);
    }

    public static OERDefinition.Builder enumeration(Object... items) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.ENUM)).items(items);
    }

    public static OERDefinition.Builder choice(Object... items) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.CHOICE)).items(items);
    }

    public static OERDefinition.Builder placeholder() {
        return new OERDefinition.Builder((OERDefinition.BaseType)null);
    }

    public static OERDefinition.Builder seqof(Object... items) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.SEQ_OF)).items(items);
    }

    public static OERDefinition.Builder octets() {
        return (new OERDefinition.Builder(OERDefinition.BaseType.OCTET_STRING)).unbounded();
    }

    public static OERDefinition.Builder octets(int size) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.OCTET_STRING)).fixedSize((long)size);
    }

    public static OERDefinition.Builder octets(int lowerBound, int upperBound) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.OCTET_STRING)).range(BigInteger.valueOf((long)lowerBound), BigInteger.valueOf((long)upperBound));
    }

    public static OERDefinition.Builder ia5String() {
        return new OERDefinition.Builder(OERDefinition.BaseType.IA5String);
    }

    public static OERDefinition.Builder utf8String() {
        return new OERDefinition.Builder(OERDefinition.BaseType.UTF8_STRING);
    }

    public static OERDefinition.Builder utf8String(int size) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.UTF8_STRING)).rangeToMAXFrom((long)size);
    }

    public static OERDefinition.Builder utf8String(int lowerBound, int upperBound) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.UTF8_STRING)).range(BigInteger.valueOf((long)lowerBound), BigInteger.valueOf((long)upperBound));
    }

    public static OERDefinition.Builder opaque() {
        return new OERDefinition.Builder(OERDefinition.BaseType.OPAQUE);
    }

    public static List<Object> optional(Object... items) {
        return new OERDefinition.OptionalList(Arrays.asList(items));
    }

    public static OERDefinition.ExtensionList extension(Object... items) {
        return new OERDefinition.ExtensionList(1, Arrays.asList(items));
    }

    public static OERDefinition.ExtensionList extension(int block, Object... items) {
        return new OERDefinition.ExtensionList(block, Arrays.asList(items));
    }

    public static OERDefinition.Builder deferred(ElementSupplier elementSupplier) {
        return (new OERDefinition.Builder(OERDefinition.BaseType.Supplier)).elementSupplier(elementSupplier);
    }

    private static class ExtensionList extends ArrayList<Object> {
        protected final int block;

        public ExtensionList(int block, List<Object> asList) {
            this.block = block;
            this.addAll(asList);
        }
    }

    private static class OptionalList extends ArrayList<Object> {
        public OptionalList(List<Object> asList) {
            this.addAll(asList);
        }
    }

    public static class MutableBuilder extends OERDefinition.Builder {
        private boolean frozen = false;

        public MutableBuilder(OERDefinition.BaseType baseType) {
            super(baseType);
        }

        public OERDefinition.MutableBuilder label(String label) {
            this.label = label;
            return this;
        }

        public OERDefinition.MutableBuilder addItemsAndFreeze(OERDefinition.Builder... items) {
            if (this.frozen) {
                throw new IllegalStateException("build cannot be modified and must be copied only");
            } else {
                for(int i = 0; i != items.length; ++i) {
                    Object item = items[i];
                    if (item instanceof OERDefinition.OptionalList) {
                        Iterator it = ((List)item).iterator();

                        while(it.hasNext()) {
                            super.children.add(this.wrap(false, it.next()));
                        }
                    } else if (item.getClass().isArray()) {
                        Object[] var4 = (Object[])((Object[])item);
                        int var5 = var4.length;

                        for(int var6 = 0; var6 < var5; ++var6) {
                            Object o = var4[var6];
                            super.children.add(this.wrap(true, o));
                        }
                    } else {
                        super.children.add(this.wrap(true, item));
                    }
                }

                this.frozen = true;
                return this;
            }
        }
    }

    public static class Builder {
        protected final OERDefinition.BaseType baseType;
        protected ArrayList<OERDefinition.Builder> children = new ArrayList();
        protected boolean explicit = true;
        protected String typeName;
        protected String label;
        protected BigInteger upperBound;
        protected BigInteger lowerBound;
        protected BigInteger enumValue;
        protected ASN1Encodable defaultValue;
        protected OERDefinition.Builder placeholderValue;
        protected Boolean inScope;
        protected Switch aSwitch;
        protected ArrayList<ASN1Encodable> validSwitchValues = new ArrayList();
        protected ElementSupplier elementSupplier;
        protected boolean mayRecurse;
        protected Map<String, ElementSupplier> supplierMap = new HashMap();
        protected int block;
        private final OERDefinition.ItemProvider defaultItemProvider = new OERDefinition.ItemProvider() {
            public OERDefinition.Builder existingChild(int index, OERDefinition.Builder existingChild) {
                return existingChild.copy(Builder.this.defaultItemProvider);
            }
        };

        public Builder(OERDefinition.BaseType baseType) {
            this.baseType = baseType;
        }

        private OERDefinition.Builder copy(OERDefinition.ItemProvider provider) {
            OERDefinition.Builder b = new OERDefinition.Builder(this.baseType);
            int t = 0;
            Iterator it = this.children.iterator();

            while(it.hasNext()) {
                OERDefinition.Builder child = (OERDefinition.Builder)it.next();
                b.children.add(provider.existingChild(t++, child));
            }

            b.explicit = this.explicit;
            b.label = this.label;
            b.upperBound = this.upperBound;
            b.lowerBound = this.lowerBound;
            b.defaultValue = this.defaultValue;
            b.enumValue = this.enumValue;
            b.inScope = this.inScope;
            b.aSwitch = this.aSwitch;
            b.validSwitchValues = new ArrayList(this.validSwitchValues);
            b.elementSupplier = this.elementSupplier;
            b.mayRecurse = this.mayRecurse;
            b.typeName = this.typeName;
            b.supplierMap = new HashMap(this.supplierMap);
            b.block = this.block;
            return b;
        }

        protected OERDefinition.Builder block(int block) {
            OERDefinition.Builder b = this.copy();
            b.block = block;
            return b;
        }

        public OERDefinition.Builder copy() {
            return this.copy(this.defaultItemProvider);
        }

        public OERDefinition.Builder elementSupplier(ElementSupplier elementSupplier) {
            OERDefinition.Builder b = this.copy();
            b.elementSupplier = elementSupplier;
            return b;
        }

        public OERDefinition.Builder validSwitchValue(ASN1Encodable... values) {
            OERDefinition.Builder b = this.copy();
            b.validSwitchValues.addAll(Arrays.asList(values));
            return b;
        }

        public OERDefinition.Builder inScope(boolean scope) {
            OERDefinition.Builder b = this.copy();
            b.inScope = scope;
            return b;
        }

        public OERDefinition.Builder limitScopeTo(String... label) {
            OERDefinition.Builder b = this.copy();
            HashSet<String> labels = new HashSet();
            labels.addAll(Arrays.asList(label));
            ArrayList<OERDefinition.Builder> scopeLimited = new ArrayList();
            Iterator it = this.children.iterator();

            while(it.hasNext()) {
                OERDefinition.Builder child = (OERDefinition.Builder)it.next();
                scopeLimited.add(child.copy().inScope(labels.contains(child.label)));
            }

            b.children = scopeLimited;
            return b;
        }

        public OERDefinition.Builder typeName(String name) {
            OERDefinition.Builder b = this.copy();
            b.typeName = name;
            if (b.label == null) {
                b.label = name;
            }

            return b;
        }

        public OERDefinition.Builder unbounded() {
            OERDefinition.Builder b = this.copy();
            b.lowerBound = null;
            b.upperBound = null;
            return b;
        }

        public OERDefinition.Builder decodeSwitch(Switch aSwitch) {
            OERDefinition.Builder cpy = this.copy();
            cpy.aSwitch = aSwitch;
            return cpy;
        }

        public OERDefinition.Builder labelPrefix(String prefix) {
            OERDefinition.Builder cpy = this.copy();
            cpy.label = prefix + " " + this.label;
            return cpy;
        }

        public OERDefinition.Builder explicit(boolean explicit) {
            OERDefinition.Builder b = this.copy();
            b.explicit = explicit;
            return b;
        }

        public OERDefinition.Builder defaultValue(ASN1Encodable defaultValue) {
            OERDefinition.Builder b = this.copy();
            b.defaultValue = defaultValue;
            return b;
        }

        protected OERDefinition.Builder wrap(boolean explicit, Object item) {
            if (item instanceof OERDefinition.Builder) {
                return ((OERDefinition.Builder)item).explicit(explicit);
            } else if (item instanceof OERDefinition.BaseType) {
                return (new OERDefinition.Builder((OERDefinition.BaseType)item)).explicit(explicit);
            } else if (item instanceof String) {
                return OERDefinition.enumItem((String)item);
            } else {
                throw new IllegalStateException("Unable to wrap item in builder");
            }
        }

        protected void addExtensions(OERDefinition.Builder b, OERDefinition.ExtensionList extensionList) {
            if (extensionList.isEmpty()) {
                OERDefinition.Builder stub = new OERDefinition.Builder(OERDefinition.BaseType.EXTENSION);
                stub.block = extensionList.block;
                b.children.add(stub);
            } else {
                Iterator it = extensionList.iterator();

                while(it.hasNext()) {
                    Object item = it.next();
                    if (item instanceof OERDefinition.OptionalList) {
                        this.addOptionals(b, extensionList.block, (OERDefinition.OptionalList)item);
                    } else {
                        OERDefinition.Builder wrapped = this.wrap(true, item);
                        wrapped.block = extensionList.block;
                        b.children.add(wrapped);
                    }
                }

            }
        }

        protected void addOptionals(OERDefinition.Builder b, int block, OERDefinition.OptionalList optionalList) {
            Iterator it = optionalList.iterator();

            while(it.hasNext()) {
                Object o = it.next();
                if (o instanceof OERDefinition.ExtensionList) {
                    this.addExtensions(b, (OERDefinition.ExtensionList)o);
                } else {
                    OERDefinition.Builder wrapped = this.wrap(false, o);
                    wrapped.block = block;
                    b.children.add(wrapped);
                }
            }

        }

        public OERDefinition.Builder items(Object... items) {
            OERDefinition.Builder b = this.copy();

            for(int i = 0; i != items.length; ++i) {
                Object item = items[i];
                if (item instanceof OERDefinition.ExtensionList) {
                    this.addExtensions(b, (OERDefinition.ExtensionList)item);
                } else if (item instanceof OERDefinition.OptionalList) {
                    this.addOptionals(b, b.block, (OERDefinition.OptionalList)item);
                } else if (item.getClass().isArray()) {
                    for(int t = 0; t < ((Object[])((Object[])item)).length; ++t) {
                        b.children.add(this.wrap(true, ((Object[])((Object[])item))[t]));
                    }
                } else {
                    b.children.add(this.wrap(true, item));
                }
            }

            return b;
        }

        public OERDefinition.Builder label(String label) {
            OERDefinition.Builder newBuilder = this.copy();
            newBuilder.label = label;
            return newBuilder;
        }

        public OERDefinition.Builder mayRecurse(boolean val) {
            OERDefinition.Builder b = this.copy();
            b.mayRecurse = val;
            return b;
        }

        public Element build() {
            List<Element> children = new ArrayList();
            boolean hasExtensions = false;
            int ordinal;
            OERDefinition.Builder child;
            if (this.baseType == OERDefinition.BaseType.ENUM) {
                ordinal = 0;
                HashSet<BigInteger> dupCheck = new HashSet();

                for(int t = 0; t < this.children.size(); ++t) {
                    child = (OERDefinition.Builder)this.children.get(t);
                    if (child.enumValue == null) {
                        child.enumValue = BigInteger.valueOf((long)ordinal);
                        ++ordinal;
                    }

                    if (dupCheck.contains(child.enumValue)) {
                        throw new IllegalStateException("duplicate enum value at index " + t);
                    }

                    dupCheck.add(child.enumValue);
                }
            }

            ordinal = 0;
            boolean defaultValuesInChildren = false;

            for(Iterator var8 = this.children.iterator(); var8.hasNext(); children.add(child.build())) {
                child = (OERDefinition.Builder)var8.next();
                if (!hasExtensions && child.block > 0) {
                    hasExtensions = true;
                }

                if (!child.explicit) {
                    ++ordinal;
                }

                if (!defaultValuesInChildren && child.defaultValue != null) {
                    defaultValuesInChildren = true;
                }
            }

            return new Element(this.baseType, children, this.defaultValue == null && this.explicit, this.label, this.lowerBound, this.upperBound, hasExtensions, this.enumValue, this.defaultValue, this.aSwitch, this.validSwitchValues.isEmpty() ? null : this.validSwitchValues, this.elementSupplier, this.mayRecurse, this.typeName, this.supplierMap.isEmpty() ? null : this.supplierMap, this.block, ordinal, defaultValuesInChildren);
        }

        public OERDefinition.Builder range(BigInteger lower, BigInteger upper) {
            OERDefinition.Builder newBuilder = this.copy();
            newBuilder.lowerBound = lower;
            newBuilder.upperBound = upper;
            return newBuilder;
        }

        public OERDefinition.Builder rangeToMAXFrom(long from) {
            OERDefinition.Builder b = this.copy();
            b.lowerBound = BigInteger.valueOf(from);
            b.upperBound = null;
            return b;
        }

        public OERDefinition.Builder rangeZeroTo(long max) {
            OERDefinition.Builder b = this.copy();
            b.upperBound = BigInteger.valueOf(max);
            b.lowerBound = BigInteger.ZERO;
            return b;
        }

        public OERDefinition.Builder fixedSize(long size) {
            OERDefinition.Builder b = this.copy();
            b.upperBound = BigInteger.valueOf(size);
            b.lowerBound = BigInteger.valueOf(size);
            return b;
        }

        public OERDefinition.Builder range(long lower, long upper, ASN1Encodable defaultIntValue) {
            OERDefinition.Builder b = this.copy();
            b.lowerBound = BigInteger.valueOf(lower);
            b.upperBound = BigInteger.valueOf(upper);
            b.defaultValue = defaultIntValue;
            return b;
        }

        public OERDefinition.Builder enumValue(BigInteger value) {
            OERDefinition.Builder b = this.copy();
            this.enumValue = value;
            return b;
        }

        public OERDefinition.Builder replaceChild(final int index, final OERDefinition.Builder newItem) {
            return this.copy(new OERDefinition.ItemProvider() {
                public OERDefinition.Builder existingChild(int _index, OERDefinition.Builder existingChild) {
                    return index == _index ? newItem : existingChild;
                }
            });
        }
    }

    public interface ItemProvider {
        OERDefinition.Builder existingChild(int var1, OERDefinition.Builder var2);
    }

    public static enum BaseType {
        SEQ,
        SEQ_OF,
        CHOICE,
        ENUM,
        INT,
        OCTET_STRING,
        OPAQUE,
        UTF8_STRING,
        BIT_STRING,
        NULL,
        EXTENSION,
        ENUM_ITEM,
        BOOLEAN,
        IS0646String,
        PrintableString,
        NumericString,
        BMPString,
        UniversalString,
        IA5String,
        VisibleString,
        Switch,
        Supplier;

        private BaseType() {
        }
    }
}