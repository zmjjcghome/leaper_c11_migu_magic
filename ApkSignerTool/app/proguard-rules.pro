# ============================================================
# apksig 核心保留规则（必须）
# apksig 通过反射实例化 ASN.1 编码器、签名算法工厂等内部类
# ============================================================
-keep class com.android.apksig.** { *; }
-keepclassmembers class com.android.apksig.** { *; }
-dontwarn com.android.apksig.**

# ============================================================
# BouncyCastle 完整保留规则（必须）
# BC 的 ASN.1/PKCS#7 编码器全部通过反射和 Class.forName 加载
# R8 无法静态分析这些调用，必须全量保留
# ============================================================
-keep class org.bouncycastle.** { *; }
-keepclassmembers class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# ============================================================
# Java Security / Crypto API 保留（关键）
# Signature、MessageDigest、KeyFactory 等通过 Provider 机制动态加载
# ============================================================
-keep class java.security.** { *; }
-keepclassmembers class java.security.** { *; }
-keep class javax.crypto.** { *; }
-keepclassmembers class javax.crypto.** { *; }

# 保留所有 Security Provider 注册信息
-keepattributes Signature, InnerClasses, EnclosingMethod
-keepclassmembers class * implements java.security.Provider { *; }
