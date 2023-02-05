// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: test.proto

package com.mi.car.jsse.easysec.micar.jsse;

/**
 * Protobuf type {@code jsse.generateSignatureParam}
 */
public  final class generateSignatureParam extends
    com.google.protobuf.GeneratedMessageLite<
        generateSignatureParam, generateSignatureParam.Builder> implements
    // @@protoc_insertion_point(message_implements:jsse.generateSignatureParam)
    generateSignatureParamOrBuilder {
  private generateSignatureParam() {
    signature_ = com.google.protobuf.ByteString.EMPTY;
  }
  public static final int SIGNATURE_FIELD_NUMBER = 1;
  private com.google.protobuf.ByteString signature_;
  /**
   * <code>bytes signature = 1;</code>
   * @return The signature.
   */
  @Override
  public com.google.protobuf.ByteString getSignature() {
    return signature_;
  }
  /**
   * <code>bytes signature = 1;</code>
   * @param value The signature to set.
   */
  private void setSignature(com.google.protobuf.ByteString value) {
    Class<?> valueClass = value.getClass();
  
    signature_ = value;
  }
  /**
   * <code>bytes signature = 1;</code>
   */
  private void clearSignature() {
    
    signature_ = getDefaultInstance().getSignature();
  }

  public static generateSignatureParam parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data);
  }
  public static generateSignatureParam parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data, extensionRegistry);
  }
  public static generateSignatureParam parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data);
  }
  public static generateSignatureParam parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data, extensionRegistry);
  }
  public static generateSignatureParam parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data);
  }
  public static generateSignatureParam parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, data, extensionRegistry);
  }
  public static generateSignatureParam parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, input);
  }
  public static generateSignatureParam parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, input, extensionRegistry);
  }
  public static generateSignatureParam parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return parseDelimitedFrom(DEFAULT_INSTANCE, input);
  }
  public static generateSignatureParam parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return parseDelimitedFrom(DEFAULT_INSTANCE, input, extensionRegistry);
  }
  public static generateSignatureParam parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, input);
  }
  public static generateSignatureParam parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageLite.parseFrom(
        DEFAULT_INSTANCE, input, extensionRegistry);
  }

  public static Builder newBuilder() {
    return (Builder) DEFAULT_INSTANCE.createBuilder();
  }
  public static Builder newBuilder(generateSignatureParam prototype) {
    return (Builder) DEFAULT_INSTANCE.createBuilder(prototype);
  }

  /**
   * Protobuf type {@code jsse.generateSignatureParam}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageLite.Builder<
        generateSignatureParam, Builder> implements
      // @@protoc_insertion_point(builder_implements:jsse.generateSignatureParam)
      generateSignatureParamOrBuilder {
    // Construct using com.mi.car.jsse.easysec.micar.jsse.generateSignatureParam.newBuilder()
    private Builder() {
      super(DEFAULT_INSTANCE);
    }


    /**
     * <code>bytes signature = 1;</code>
     * @return The signature.
     */
    @Override
    public com.google.protobuf.ByteString getSignature() {
      return instance.getSignature();
    }
    /**
     * <code>bytes signature = 1;</code>
     * @param value The signature to set.
     * @return This builder for chaining.
     */
    public Builder setSignature(com.google.protobuf.ByteString value) {
      copyOnWrite();
      instance.setSignature(value);
      return this;
    }
    /**
     * <code>bytes signature = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearSignature() {
      copyOnWrite();
      instance.clearSignature();
      return this;
    }

    // @@protoc_insertion_point(builder_scope:jsse.generateSignatureParam)
  }
  @Override
  @SuppressWarnings({"unchecked", "fallthrough"})
  protected final Object dynamicMethod(
      MethodToInvoke method,
      Object arg0, Object arg1) {
    switch (method) {
      case NEW_MUTABLE_INSTANCE: {
        return new generateSignatureParam();
      }
      case NEW_BUILDER: {
        return new Builder();
      }
      case BUILD_MESSAGE_INFO: {
          Object[] objects = new Object[] {
            "signature_",
          };
          String info =
              "\u0000\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0000\u0000\u0001\n";
          return newMessageInfo(DEFAULT_INSTANCE, info, objects);
      }
      // fall through
      case GET_DEFAULT_INSTANCE: {
        return DEFAULT_INSTANCE;
      }
      case GET_PARSER: {
        com.google.protobuf.Parser<generateSignatureParam> parser = PARSER;
        if (parser == null) {
          synchronized (generateSignatureParam.class) {
            parser = PARSER;
            if (parser == null) {
              parser =
                  new DefaultInstanceBasedParser<generateSignatureParam>(
                      DEFAULT_INSTANCE);
              PARSER = parser;
            }
          }
        }
        return parser;
    }
    case GET_MEMOIZED_IS_INITIALIZED: {
      return (byte) 1;
    }
    case SET_MEMOIZED_IS_INITIALIZED: {
      return null;
    }
    }
    throw new UnsupportedOperationException();
  }


  // @@protoc_insertion_point(class_scope:jsse.generateSignatureParam)
  private static final generateSignatureParam DEFAULT_INSTANCE;
  static {
    generateSignatureParam defaultInstance = new generateSignatureParam();
    // New instances are implicitly immutable so no need to make
    // immutable.
    DEFAULT_INSTANCE = defaultInstance;
    com.google.protobuf.GeneratedMessageLite.registerDefaultInstance(
      generateSignatureParam.class, defaultInstance);
  }

  public static generateSignatureParam getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static volatile com.google.protobuf.Parser<generateSignatureParam> PARSER;

  public static com.google.protobuf.Parser<generateSignatureParam> parser() {
    return DEFAULT_INSTANCE.getParserForType();
  }
}

