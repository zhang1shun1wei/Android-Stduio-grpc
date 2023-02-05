package com.mi.car.jsse.easysec.jce;

import com.mi.car.jsse.easysec.x509.X509StoreParameters;
import java.security.cert.CertStoreParameters;
import java.security.cert.LDAPCertStoreParameters;

public class X509LDAPCertStoreParameters implements X509StoreParameters, CertStoreParameters {
    private String aACertificateAttribute;
    private String aACertificateSubjectAttributeName;
    private String attributeAuthorityRevocationListAttribute;
    private String attributeAuthorityRevocationListIssuerAttributeName;
    private String attributeCertificateAttributeAttribute;
    private String attributeCertificateAttributeSubjectAttributeName;
    private String attributeCertificateRevocationListAttribute;
    private String attributeCertificateRevocationListIssuerAttributeName;
    private String attributeDescriptorCertificateAttribute;
    private String attributeDescriptorCertificateSubjectAttributeName;
    private String authorityRevocationListAttribute;
    private String authorityRevocationListIssuerAttributeName;
    private String baseDN;
    private String cACertificateAttribute;
    private String cACertificateSubjectAttributeName;
    private String certificateRevocationListAttribute;
    private String certificateRevocationListIssuerAttributeName;
    private String crossCertificateAttribute;
    private String crossCertificateSubjectAttributeName;
    private String deltaRevocationListAttribute;
    private String deltaRevocationListIssuerAttributeName;
    private String ldapAACertificateAttributeName;
    private String ldapAttributeAuthorityRevocationListAttributeName;
    private String ldapAttributeCertificateAttributeAttributeName;
    private String ldapAttributeCertificateRevocationListAttributeName;
    private String ldapAttributeDescriptorCertificateAttributeName;
    private String ldapAuthorityRevocationListAttributeName;
    private String ldapCACertificateAttributeName;
    private String ldapCertificateRevocationListAttributeName;
    private String ldapCrossCertificateAttributeName;
    private String ldapDeltaRevocationListAttributeName;
    private String ldapURL;
    private String ldapUserCertificateAttributeName;
    private String searchForSerialNumberIn;
    private String userCertificateAttribute;
    private String userCertificateSubjectAttributeName;

    public static class Builder {
        private String aACertificateAttribute;
        private String aACertificateSubjectAttributeName;
        private String attributeAuthorityRevocationListAttribute;
        private String attributeAuthorityRevocationListIssuerAttributeName;
        private String attributeCertificateAttributeAttribute;
        private String attributeCertificateAttributeSubjectAttributeName;
        private String attributeCertificateRevocationListAttribute;
        private String attributeCertificateRevocationListIssuerAttributeName;
        private String attributeDescriptorCertificateAttribute;
        private String attributeDescriptorCertificateSubjectAttributeName;
        private String authorityRevocationListAttribute;
        private String authorityRevocationListIssuerAttributeName;
        private String baseDN;
        private String cACertificateAttribute;
        private String cACertificateSubjectAttributeName;
        private String certificateRevocationListAttribute;
        private String certificateRevocationListIssuerAttributeName;
        private String crossCertificateAttribute;
        private String crossCertificateSubjectAttributeName;
        private String deltaRevocationListAttribute;
        private String deltaRevocationListIssuerAttributeName;
        private String ldapAACertificateAttributeName;
        private String ldapAttributeAuthorityRevocationListAttributeName;
        private String ldapAttributeCertificateAttributeAttributeName;
        private String ldapAttributeCertificateRevocationListAttributeName;
        private String ldapAttributeDescriptorCertificateAttributeName;
        private String ldapAuthorityRevocationListAttributeName;
        private String ldapCACertificateAttributeName;
        private String ldapCertificateRevocationListAttributeName;
        private String ldapCrossCertificateAttributeName;
        private String ldapDeltaRevocationListAttributeName;
        private String ldapURL;
        private String ldapUserCertificateAttributeName;
        private String searchForSerialNumberIn;
        private String userCertificateAttribute;
        private String userCertificateSubjectAttributeName;

        public Builder() {
            this("ldap://localhost:389", "");
        }

        public Builder(String ldapURL2, String baseDN2) {
            this.ldapURL = ldapURL2;
            if (baseDN2 == null) {
                this.baseDN = "";
            } else {
                this.baseDN = baseDN2;
            }
            this.userCertificateAttribute = "userCertificate";
            this.cACertificateAttribute = "cACertificate";
            this.crossCertificateAttribute = "crossCertificatePair";
            this.certificateRevocationListAttribute = "certificateRevocationList";
            this.deltaRevocationListAttribute = "deltaRevocationList";
            this.authorityRevocationListAttribute = "authorityRevocationList";
            this.attributeCertificateAttributeAttribute = "attributeCertificateAttribute";
            this.aACertificateAttribute = "aACertificate";
            this.attributeDescriptorCertificateAttribute = "attributeDescriptorCertificate";
            this.attributeCertificateRevocationListAttribute = "attributeCertificateRevocationList";
            this.attributeAuthorityRevocationListAttribute = "attributeAuthorityRevocationList";
            this.ldapUserCertificateAttributeName = "cn";
            this.ldapCACertificateAttributeName = "cn ou o";
            this.ldapCrossCertificateAttributeName = "cn ou o";
            this.ldapCertificateRevocationListAttributeName = "cn ou o";
            this.ldapDeltaRevocationListAttributeName = "cn ou o";
            this.ldapAuthorityRevocationListAttributeName = "cn ou o";
            this.ldapAttributeCertificateAttributeAttributeName = "cn";
            this.ldapAACertificateAttributeName = "cn o ou";
            this.ldapAttributeDescriptorCertificateAttributeName = "cn o ou";
            this.ldapAttributeCertificateRevocationListAttributeName = "cn o ou";
            this.ldapAttributeAuthorityRevocationListAttributeName = "cn o ou";
            this.userCertificateSubjectAttributeName = "cn";
            this.cACertificateSubjectAttributeName = "o ou";
            this.crossCertificateSubjectAttributeName = "o ou";
            this.certificateRevocationListIssuerAttributeName = "o ou";
            this.deltaRevocationListIssuerAttributeName = "o ou";
            this.authorityRevocationListIssuerAttributeName = "o ou";
            this.attributeCertificateAttributeSubjectAttributeName = "cn";
            this.aACertificateSubjectAttributeName = "o ou";
            this.attributeDescriptorCertificateSubjectAttributeName = "o ou";
            this.attributeCertificateRevocationListIssuerAttributeName = "o ou";
            this.attributeAuthorityRevocationListIssuerAttributeName = "o ou";
            this.searchForSerialNumberIn = "uid serialNumber cn";
        }

        public Builder setUserCertificateAttribute(String userCertificateAttribute2) {
            this.userCertificateAttribute = userCertificateAttribute2;
            return this;
        }

        public Builder setCACertificateAttribute(String cACertificateAttribute2) {
            this.cACertificateAttribute = cACertificateAttribute2;
            return this;
        }

        public Builder setCrossCertificateAttribute(String crossCertificateAttribute2) {
            this.crossCertificateAttribute = crossCertificateAttribute2;
            return this;
        }

        public Builder setCertificateRevocationListAttribute(String certificateRevocationListAttribute2) {
            this.certificateRevocationListAttribute = certificateRevocationListAttribute2;
            return this;
        }

        public Builder setDeltaRevocationListAttribute(String deltaRevocationListAttribute2) {
            this.deltaRevocationListAttribute = deltaRevocationListAttribute2;
            return this;
        }

        public Builder setAuthorityRevocationListAttribute(String authorityRevocationListAttribute2) {
            this.authorityRevocationListAttribute = authorityRevocationListAttribute2;
            return this;
        }

        public Builder setAttributeCertificateAttributeAttribute(String attributeCertificateAttributeAttribute2) {
            this.attributeCertificateAttributeAttribute = attributeCertificateAttributeAttribute2;
            return this;
        }

        public Builder setAACertificateAttribute(String aACertificateAttribute2) {
            this.aACertificateAttribute = aACertificateAttribute2;
            return this;
        }

        public Builder setAttributeDescriptorCertificateAttribute(String attributeDescriptorCertificateAttribute2) {
            this.attributeDescriptorCertificateAttribute = attributeDescriptorCertificateAttribute2;
            return this;
        }

        public Builder setAttributeCertificateRevocationListAttribute(String attributeCertificateRevocationListAttribute2) {
            this.attributeCertificateRevocationListAttribute = attributeCertificateRevocationListAttribute2;
            return this;
        }

        public Builder setAttributeAuthorityRevocationListAttribute(String attributeAuthorityRevocationListAttribute2) {
            this.attributeAuthorityRevocationListAttribute = attributeAuthorityRevocationListAttribute2;
            return this;
        }

        public Builder setLdapUserCertificateAttributeName(String ldapUserCertificateAttributeName2) {
            this.ldapUserCertificateAttributeName = ldapUserCertificateAttributeName2;
            return this;
        }

        public Builder setLdapCACertificateAttributeName(String ldapCACertificateAttributeName2) {
            this.ldapCACertificateAttributeName = ldapCACertificateAttributeName2;
            return this;
        }

        public Builder setLdapCrossCertificateAttributeName(String ldapCrossCertificateAttributeName2) {
            this.ldapCrossCertificateAttributeName = ldapCrossCertificateAttributeName2;
            return this;
        }

        public Builder setLdapCertificateRevocationListAttributeName(String ldapCertificateRevocationListAttributeName2) {
            this.ldapCertificateRevocationListAttributeName = ldapCertificateRevocationListAttributeName2;
            return this;
        }

        public Builder setLdapDeltaRevocationListAttributeName(String ldapDeltaRevocationListAttributeName2) {
            this.ldapDeltaRevocationListAttributeName = ldapDeltaRevocationListAttributeName2;
            return this;
        }

        public Builder setLdapAuthorityRevocationListAttributeName(String ldapAuthorityRevocationListAttributeName2) {
            this.ldapAuthorityRevocationListAttributeName = ldapAuthorityRevocationListAttributeName2;
            return this;
        }

        public Builder setLdapAttributeCertificateAttributeAttributeName(String ldapAttributeCertificateAttributeAttributeName2) {
            this.ldapAttributeCertificateAttributeAttributeName = ldapAttributeCertificateAttributeAttributeName2;
            return this;
        }

        public Builder setLdapAACertificateAttributeName(String ldapAACertificateAttributeName2) {
            this.ldapAACertificateAttributeName = ldapAACertificateAttributeName2;
            return this;
        }

        public Builder setLdapAttributeDescriptorCertificateAttributeName(String ldapAttributeDescriptorCertificateAttributeName2) {
            this.ldapAttributeDescriptorCertificateAttributeName = ldapAttributeDescriptorCertificateAttributeName2;
            return this;
        }

        public Builder setLdapAttributeCertificateRevocationListAttributeName(String ldapAttributeCertificateRevocationListAttributeName2) {
            this.ldapAttributeCertificateRevocationListAttributeName = ldapAttributeCertificateRevocationListAttributeName2;
            return this;
        }

        public Builder setLdapAttributeAuthorityRevocationListAttributeName(String ldapAttributeAuthorityRevocationListAttributeName2) {
            this.ldapAttributeAuthorityRevocationListAttributeName = ldapAttributeAuthorityRevocationListAttributeName2;
            return this;
        }

        public Builder setUserCertificateSubjectAttributeName(String userCertificateSubjectAttributeName2) {
            this.userCertificateSubjectAttributeName = userCertificateSubjectAttributeName2;
            return this;
        }

        public Builder setCACertificateSubjectAttributeName(String cACertificateSubjectAttributeName2) {
            this.cACertificateSubjectAttributeName = cACertificateSubjectAttributeName2;
            return this;
        }

        public Builder setCrossCertificateSubjectAttributeName(String crossCertificateSubjectAttributeName2) {
            this.crossCertificateSubjectAttributeName = crossCertificateSubjectAttributeName2;
            return this;
        }

        public Builder setCertificateRevocationListIssuerAttributeName(String certificateRevocationListIssuerAttributeName2) {
            this.certificateRevocationListIssuerAttributeName = certificateRevocationListIssuerAttributeName2;
            return this;
        }

        public Builder setDeltaRevocationListIssuerAttributeName(String deltaRevocationListIssuerAttributeName2) {
            this.deltaRevocationListIssuerAttributeName = deltaRevocationListIssuerAttributeName2;
            return this;
        }

        public Builder setAuthorityRevocationListIssuerAttributeName(String authorityRevocationListIssuerAttributeName2) {
            this.authorityRevocationListIssuerAttributeName = authorityRevocationListIssuerAttributeName2;
            return this;
        }

        public Builder setAttributeCertificateAttributeSubjectAttributeName(String attributeCertificateAttributeSubjectAttributeName2) {
            this.attributeCertificateAttributeSubjectAttributeName = attributeCertificateAttributeSubjectAttributeName2;
            return this;
        }

        public Builder setAACertificateSubjectAttributeName(String aACertificateSubjectAttributeName2) {
            this.aACertificateSubjectAttributeName = aACertificateSubjectAttributeName2;
            return this;
        }

        public Builder setAttributeDescriptorCertificateSubjectAttributeName(String attributeDescriptorCertificateSubjectAttributeName2) {
            this.attributeDescriptorCertificateSubjectAttributeName = attributeDescriptorCertificateSubjectAttributeName2;
            return this;
        }

        public Builder setAttributeCertificateRevocationListIssuerAttributeName(String attributeCertificateRevocationListIssuerAttributeName2) {
            this.attributeCertificateRevocationListIssuerAttributeName = attributeCertificateRevocationListIssuerAttributeName2;
            return this;
        }

        public Builder setAttributeAuthorityRevocationListIssuerAttributeName(String attributeAuthorityRevocationListIssuerAttributeName2) {
            this.attributeAuthorityRevocationListIssuerAttributeName = attributeAuthorityRevocationListIssuerAttributeName2;
            return this;
        }

        public Builder setSearchForSerialNumberIn(String searchForSerialNumberIn2) {
            this.searchForSerialNumberIn = searchForSerialNumberIn2;
            return this;
        }

        public X509LDAPCertStoreParameters build() {
            if (this.ldapUserCertificateAttributeName != null && this.ldapCACertificateAttributeName != null && this.ldapCrossCertificateAttributeName != null && this.ldapCertificateRevocationListAttributeName != null && this.ldapDeltaRevocationListAttributeName != null && this.ldapAuthorityRevocationListAttributeName != null && this.ldapAttributeCertificateAttributeAttributeName != null && this.ldapAACertificateAttributeName != null && this.ldapAttributeDescriptorCertificateAttributeName != null && this.ldapAttributeCertificateRevocationListAttributeName != null && this.ldapAttributeAuthorityRevocationListAttributeName != null && this.userCertificateSubjectAttributeName != null && this.cACertificateSubjectAttributeName != null && this.crossCertificateSubjectAttributeName != null && this.certificateRevocationListIssuerAttributeName != null && this.deltaRevocationListIssuerAttributeName != null && this.authorityRevocationListIssuerAttributeName != null && this.attributeCertificateAttributeSubjectAttributeName != null && this.aACertificateSubjectAttributeName != null && this.attributeDescriptorCertificateSubjectAttributeName != null && this.attributeCertificateRevocationListIssuerAttributeName != null && this.attributeAuthorityRevocationListIssuerAttributeName != null) {
                return new X509LDAPCertStoreParameters(this);
            }
            throw new IllegalArgumentException("Necessary parameters not specified.");
        }
    }

    private X509LDAPCertStoreParameters(Builder builder) {
        this.ldapURL = builder.ldapURL;
        this.baseDN = builder.baseDN;
        this.userCertificateAttribute = builder.userCertificateAttribute;
        this.cACertificateAttribute = builder.cACertificateAttribute;
        this.crossCertificateAttribute = builder.crossCertificateAttribute;
        this.certificateRevocationListAttribute = builder.certificateRevocationListAttribute;
        this.deltaRevocationListAttribute = builder.deltaRevocationListAttribute;
        this.authorityRevocationListAttribute = builder.authorityRevocationListAttribute;
        this.attributeCertificateAttributeAttribute = builder.attributeCertificateAttributeAttribute;
        this.aACertificateAttribute = builder.aACertificateAttribute;
        this.attributeDescriptorCertificateAttribute = builder.attributeDescriptorCertificateAttribute;
        this.attributeCertificateRevocationListAttribute = builder.attributeCertificateRevocationListAttribute;
        this.attributeAuthorityRevocationListAttribute = builder.attributeAuthorityRevocationListAttribute;
        this.ldapUserCertificateAttributeName = builder.ldapUserCertificateAttributeName;
        this.ldapCACertificateAttributeName = builder.ldapCACertificateAttributeName;
        this.ldapCrossCertificateAttributeName = builder.ldapCrossCertificateAttributeName;
        this.ldapCertificateRevocationListAttributeName = builder.ldapCertificateRevocationListAttributeName;
        this.ldapDeltaRevocationListAttributeName = builder.ldapDeltaRevocationListAttributeName;
        this.ldapAuthorityRevocationListAttributeName = builder.ldapAuthorityRevocationListAttributeName;
        this.ldapAttributeCertificateAttributeAttributeName = builder.ldapAttributeCertificateAttributeAttributeName;
        this.ldapAACertificateAttributeName = builder.ldapAACertificateAttributeName;
        this.ldapAttributeDescriptorCertificateAttributeName = builder.ldapAttributeDescriptorCertificateAttributeName;
        this.ldapAttributeCertificateRevocationListAttributeName = builder.ldapAttributeCertificateRevocationListAttributeName;
        this.ldapAttributeAuthorityRevocationListAttributeName = builder.ldapAttributeAuthorityRevocationListAttributeName;
        this.userCertificateSubjectAttributeName = builder.userCertificateSubjectAttributeName;
        this.cACertificateSubjectAttributeName = builder.cACertificateSubjectAttributeName;
        this.crossCertificateSubjectAttributeName = builder.crossCertificateSubjectAttributeName;
        this.certificateRevocationListIssuerAttributeName = builder.certificateRevocationListIssuerAttributeName;
        this.deltaRevocationListIssuerAttributeName = builder.deltaRevocationListIssuerAttributeName;
        this.authorityRevocationListIssuerAttributeName = builder.authorityRevocationListIssuerAttributeName;
        this.attributeCertificateAttributeSubjectAttributeName = builder.attributeCertificateAttributeSubjectAttributeName;
        this.aACertificateSubjectAttributeName = builder.aACertificateSubjectAttributeName;
        this.attributeDescriptorCertificateSubjectAttributeName = builder.attributeDescriptorCertificateSubjectAttributeName;
        this.attributeCertificateRevocationListIssuerAttributeName = builder.attributeCertificateRevocationListIssuerAttributeName;
        this.attributeAuthorityRevocationListIssuerAttributeName = builder.attributeAuthorityRevocationListIssuerAttributeName;
        this.searchForSerialNumberIn = builder.searchForSerialNumberIn;
    }

    @Override // java.lang.Object
    public Object clone() {
        return this;
    }

    public boolean equal(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof X509LDAPCertStoreParameters)) {
            return false;
        }
        X509LDAPCertStoreParameters params = (X509LDAPCertStoreParameters) o;
        return checkField(this.ldapURL, params.ldapURL) && checkField(this.baseDN, params.baseDN) && checkField(this.userCertificateAttribute, params.userCertificateAttribute) && checkField(this.cACertificateAttribute, params.cACertificateAttribute) && checkField(this.crossCertificateAttribute, params.crossCertificateAttribute) && checkField(this.certificateRevocationListAttribute, params.certificateRevocationListAttribute) && checkField(this.deltaRevocationListAttribute, params.deltaRevocationListAttribute) && checkField(this.authorityRevocationListAttribute, params.authorityRevocationListAttribute) && checkField(this.attributeCertificateAttributeAttribute, params.attributeCertificateAttributeAttribute) && checkField(this.aACertificateAttribute, params.aACertificateAttribute) && checkField(this.attributeDescriptorCertificateAttribute, params.attributeDescriptorCertificateAttribute) && checkField(this.attributeCertificateRevocationListAttribute, params.attributeCertificateRevocationListAttribute) && checkField(this.attributeAuthorityRevocationListAttribute, params.attributeAuthorityRevocationListAttribute) && checkField(this.ldapUserCertificateAttributeName, params.ldapUserCertificateAttributeName) && checkField(this.ldapCACertificateAttributeName, params.ldapCACertificateAttributeName) && checkField(this.ldapCrossCertificateAttributeName, params.ldapCrossCertificateAttributeName) && checkField(this.ldapCertificateRevocationListAttributeName, params.ldapCertificateRevocationListAttributeName) && checkField(this.ldapDeltaRevocationListAttributeName, params.ldapDeltaRevocationListAttributeName) && checkField(this.ldapAuthorityRevocationListAttributeName, params.ldapAuthorityRevocationListAttributeName) && checkField(this.ldapAttributeCertificateAttributeAttributeName, params.ldapAttributeCertificateAttributeAttributeName) && checkField(this.ldapAACertificateAttributeName, params.ldapAACertificateAttributeName) && checkField(this.ldapAttributeDescriptorCertificateAttributeName, params.ldapAttributeDescriptorCertificateAttributeName) && checkField(this.ldapAttributeCertificateRevocationListAttributeName, params.ldapAttributeCertificateRevocationListAttributeName) && checkField(this.ldapAttributeAuthorityRevocationListAttributeName, params.ldapAttributeAuthorityRevocationListAttributeName) && checkField(this.userCertificateSubjectAttributeName, params.userCertificateSubjectAttributeName) && checkField(this.cACertificateSubjectAttributeName, params.cACertificateSubjectAttributeName) && checkField(this.crossCertificateSubjectAttributeName, params.crossCertificateSubjectAttributeName) && checkField(this.certificateRevocationListIssuerAttributeName, params.certificateRevocationListIssuerAttributeName) && checkField(this.deltaRevocationListIssuerAttributeName, params.deltaRevocationListIssuerAttributeName) && checkField(this.authorityRevocationListIssuerAttributeName, params.authorityRevocationListIssuerAttributeName) && checkField(this.attributeCertificateAttributeSubjectAttributeName, params.attributeCertificateAttributeSubjectAttributeName) && checkField(this.aACertificateSubjectAttributeName, params.aACertificateSubjectAttributeName) && checkField(this.attributeDescriptorCertificateSubjectAttributeName, params.attributeDescriptorCertificateSubjectAttributeName) && checkField(this.attributeCertificateRevocationListIssuerAttributeName, params.attributeCertificateRevocationListIssuerAttributeName) && checkField(this.attributeAuthorityRevocationListIssuerAttributeName, params.attributeAuthorityRevocationListIssuerAttributeName) && checkField(this.searchForSerialNumberIn, params.searchForSerialNumberIn);
    }

    private boolean checkField(Object o1, Object o2) {
        if (o1 == o2) {
            return true;
        }
        if (o1 == null) {
            return false;
        }
        return o1.equals(o2);
    }

    public int hashCode() {
        return addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(addHashCode(0, this.userCertificateAttribute), this.cACertificateAttribute), this.crossCertificateAttribute), this.certificateRevocationListAttribute), this.deltaRevocationListAttribute), this.authorityRevocationListAttribute), this.attributeCertificateAttributeAttribute), this.aACertificateAttribute), this.attributeDescriptorCertificateAttribute), this.attributeCertificateRevocationListAttribute), this.attributeAuthorityRevocationListAttribute), this.ldapUserCertificateAttributeName), this.ldapCACertificateAttributeName), this.ldapCrossCertificateAttributeName), this.ldapCertificateRevocationListAttributeName), this.ldapDeltaRevocationListAttributeName), this.ldapAuthorityRevocationListAttributeName), this.ldapAttributeCertificateAttributeAttributeName), this.ldapAACertificateAttributeName), this.ldapAttributeDescriptorCertificateAttributeName), this.ldapAttributeCertificateRevocationListAttributeName), this.ldapAttributeAuthorityRevocationListAttributeName), this.userCertificateSubjectAttributeName), this.cACertificateSubjectAttributeName), this.crossCertificateSubjectAttributeName), this.certificateRevocationListIssuerAttributeName), this.deltaRevocationListIssuerAttributeName), this.authorityRevocationListIssuerAttributeName), this.attributeCertificateAttributeSubjectAttributeName), this.aACertificateSubjectAttributeName), this.attributeDescriptorCertificateSubjectAttributeName), this.attributeCertificateRevocationListIssuerAttributeName), this.attributeAuthorityRevocationListIssuerAttributeName), this.searchForSerialNumberIn);
    }

    private int addHashCode(int hashCode, Object o) {
        return (o == null ? 0 : o.hashCode()) + (hashCode * 29);
    }

    public String getAACertificateAttribute() {
        return this.aACertificateAttribute;
    }

    public String getAACertificateSubjectAttributeName() {
        return this.aACertificateSubjectAttributeName;
    }

    public String getAttributeAuthorityRevocationListAttribute() {
        return this.attributeAuthorityRevocationListAttribute;
    }

    public String getAttributeAuthorityRevocationListIssuerAttributeName() {
        return this.attributeAuthorityRevocationListIssuerAttributeName;
    }

    public String getAttributeCertificateAttributeAttribute() {
        return this.attributeCertificateAttributeAttribute;
    }

    public String getAttributeCertificateAttributeSubjectAttributeName() {
        return this.attributeCertificateAttributeSubjectAttributeName;
    }

    public String getAttributeCertificateRevocationListAttribute() {
        return this.attributeCertificateRevocationListAttribute;
    }

    public String getAttributeCertificateRevocationListIssuerAttributeName() {
        return this.attributeCertificateRevocationListIssuerAttributeName;
    }

    public String getAttributeDescriptorCertificateAttribute() {
        return this.attributeDescriptorCertificateAttribute;
    }

    public String getAttributeDescriptorCertificateSubjectAttributeName() {
        return this.attributeDescriptorCertificateSubjectAttributeName;
    }

    public String getAuthorityRevocationListAttribute() {
        return this.authorityRevocationListAttribute;
    }

    public String getAuthorityRevocationListIssuerAttributeName() {
        return this.authorityRevocationListIssuerAttributeName;
    }

    public String getBaseDN() {
        return this.baseDN;
    }

    public String getCACertificateAttribute() {
        return this.cACertificateAttribute;
    }

    public String getCACertificateSubjectAttributeName() {
        return this.cACertificateSubjectAttributeName;
    }

    public String getCertificateRevocationListAttribute() {
        return this.certificateRevocationListAttribute;
    }

    public String getCertificateRevocationListIssuerAttributeName() {
        return this.certificateRevocationListIssuerAttributeName;
    }

    public String getCrossCertificateAttribute() {
        return this.crossCertificateAttribute;
    }

    public String getCrossCertificateSubjectAttributeName() {
        return this.crossCertificateSubjectAttributeName;
    }

    public String getDeltaRevocationListAttribute() {
        return this.deltaRevocationListAttribute;
    }

    public String getDeltaRevocationListIssuerAttributeName() {
        return this.deltaRevocationListIssuerAttributeName;
    }

    public String getLdapAACertificateAttributeName() {
        return this.ldapAACertificateAttributeName;
    }

    public String getLdapAttributeAuthorityRevocationListAttributeName() {
        return this.ldapAttributeAuthorityRevocationListAttributeName;
    }

    public String getLdapAttributeCertificateAttributeAttributeName() {
        return this.ldapAttributeCertificateAttributeAttributeName;
    }

    public String getLdapAttributeCertificateRevocationListAttributeName() {
        return this.ldapAttributeCertificateRevocationListAttributeName;
    }

    public String getLdapAttributeDescriptorCertificateAttributeName() {
        return this.ldapAttributeDescriptorCertificateAttributeName;
    }

    public String getLdapAuthorityRevocationListAttributeName() {
        return this.ldapAuthorityRevocationListAttributeName;
    }

    public String getLdapCACertificateAttributeName() {
        return this.ldapCACertificateAttributeName;
    }

    public String getLdapCertificateRevocationListAttributeName() {
        return this.ldapCertificateRevocationListAttributeName;
    }

    public String getLdapCrossCertificateAttributeName() {
        return this.ldapCrossCertificateAttributeName;
    }

    public String getLdapDeltaRevocationListAttributeName() {
        return this.ldapDeltaRevocationListAttributeName;
    }

    public String getLdapURL() {
        return this.ldapURL;
    }

    public String getLdapUserCertificateAttributeName() {
        return this.ldapUserCertificateAttributeName;
    }

    public String getSearchForSerialNumberIn() {
        return this.searchForSerialNumberIn;
    }

    public String getUserCertificateAttribute() {
        return this.userCertificateAttribute;
    }

    public String getUserCertificateSubjectAttributeName() {
        return this.userCertificateSubjectAttributeName;
    }

    public static X509LDAPCertStoreParameters getInstance(LDAPCertStoreParameters params) {
        return new Builder("ldap://" + params.getServerName() + ":" + params.getPort(), "").build();
    }
}
