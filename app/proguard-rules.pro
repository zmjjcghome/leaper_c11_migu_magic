# ============================================================
# 1. apksig 核心保留（签名引擎、ASN.1 编码器、ZIP 处理）
# apksig 内部通过字符串拼接类名进行反射实例化
# ============================================================
-keep class com.android.apksig.** { *; }
-keepclassmembers class com.android.apksig.** {
    <init>(...);
    public static ** valueOf(...);
    public static ** of(...);
}
-dontwarn com.android.apksig.**

# ============================================================
# 2. BouncyCastle 精准保留（仅保留反射入口，允许混淆内部实现）
# BC 的 ASN.1/PKCS7/CMS 编码器全部通过 Class.forName 加载
# ============================================================
-keep class org.bouncycastle.asn1.** { *; }
-keep class org.bouncycastle.crypto.** { *; }
-keep class org.bouncycastle.jcajce.** { *; }
-keep class org.bouncycastle.jce.** { *; }
-keep class org.bouncycastle.operator.** { *; }
-keep class org.bouncycastle.pkcs.** { *; }
-keep class org.bouncycastle.cert.** { *; }
-keep class org.bouncycastle.openssl.** { *; }
-keep class org.bouncycastle.util.** { *; }

# BC Provider 注册机制必须完整保留
-keep class * extends java.security.Provider { *; }
-keepclassmembers class * extends java.security.Provider {
    <init>(...);
}

-dontwarn org.bouncycastle.**

# ============================================================
# 3. Java Security / Crypto API 保留
# Signature、MessageDigest、KeyFactory 等通过 SPI 动态加载
# ============================================================
-keep class java.security.spec.** { *; }
-keep class javax.crypto.spec.** { *; }
-keepclassmembers class * implements java.security.Key {
    !private <fields>;
    !private <methods>;
}

# 保留注解和泛型信息（apksig 部分版本依赖）
-keepattributes Signature, InnerClasses, EnclosingMethod, RuntimeVisibleAnnotations


