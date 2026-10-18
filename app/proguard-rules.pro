# 保留 BouncyCastle，避免被混淆/裁剪
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**# 空文件，暂不启用混淆
