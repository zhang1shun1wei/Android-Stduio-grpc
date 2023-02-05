package com.mi.car.jsse.easysec.crypto;

public enum PasswordConverter implements CharToByteConverter {
    ASCII {
        @Override // com.mi.car.jsse.easysec.crypto.CharToByteConverter
        public String getType() {
            return "ASCII";
        }

        @Override // com.mi.car.jsse.easysec.crypto.CharToByteConverter
        public byte[] convert(char[] password) {
            return PBEParametersGenerator.PKCS5PasswordToBytes(password);
        }
    },
    UTF8 {
        @Override // com.mi.car.jsse.easysec.crypto.CharToByteConverter
        public String getType() {
            return "UTF8";
        }

        @Override // com.mi.car.jsse.easysec.crypto.CharToByteConverter
        public byte[] convert(char[] password) {
            return PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);
        }
    },
    PKCS12 {
        @Override // com.mi.car.jsse.easysec.crypto.CharToByteConverter
        public String getType() {
            return "PKCS12";
        }

        @Override // com.mi.car.jsse.easysec.crypto.CharToByteConverter
        public byte[] convert(char[] password) {
            return PBEParametersGenerator.PKCS12PasswordToBytes(password);
        }
    }
}
