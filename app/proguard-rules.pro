## ==============================================================================
# ApkSigner / apksig 混淆保护规则
# ==============================================================================
-keep class com.android.apksig.** { *; }
-dontwarn com.android.apksig.**

# ==============================================================================
# BouncyCastle 加密库混淆保护规则
# 防止内部反射、ASN.1对象映射、Provider服务加载、动态算法解析失效
# ==============================================================================
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# 保留加解密提供者接口与实现
-keep class * implements java.security.Provider { *; }
-keep class java.security.** { *; }
-keep class javax.crypto.** { *; }

# 保留注解、签名、内部类及枚举，防止 BouncyCastle / apksig 反射调用出错
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod,RuntimeVisibleAnnotations,RuntimeVisibleParameterAnnotations
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

