package com.devtools.apksigner.core

import com.android.apksig.ApkSigner
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 * APK 重签名核心引擎
 * 使用 Google 官方 apksig 库，支持 V1/V2/V3 签名
 */
object ApkResigner {

    /**
     * 对 APK 执行重签名
     * @param inputApk   原始 APK 文件（临时拷贝）
     * @param outputApk  输出签名后的 APK 文件（临时路径）
     * @param keystoreFile 证书文件（PKCS12/JKS）
     * @param password   证书密码
     * @param alias      密钥别名
     * @throws Exception 签名失败时抛出包含根因的异常
     */
    fun resign(
        inputApk: File,
        outputApk: File,
        keystoreFile: File,
        password: CharArray,
        alias: String
    ) {
        try {
            // 1. 加载证书库（兼容 PKCS12 和 JKS）
            val ks = KeyStore.getInstance("PKCS12")
            FileInputStream(keystoreFile).use { stream ->
                ks.load(stream, password)
            }

            // 2. 校验别名是否存在
            if (!ks.containsAlias(alias)) {
                val availableAliases = ks.aliases().toList()
                throw IllegalArgumentException(
                    "Keystore does not contain alias '$alias'. Available aliases: $availableAliases"
                )
            }

            // 3. 提取私钥与证书链，并进行严格类型校验
            val key = ks.getKey(alias, password) as? PrivateKey
                ?: throw IllegalArgumentException(
                    "Entry '$alias' is not a private key (actual type: ${ks.getKey(alias, password)?.javaClass?.name}). " +
                    "Please ensure it is a PrivateKeyEntry, not a TrustedCertificateEntry."
                )

            val certChain = ks.getCertificateChain(alias)
            if (certChain.isNullOrEmpty()) {
                throw IllegalArgumentException("Entry '$alias' has no certificate chain.")
            }

            val certificates = certChain.filterIsInstance<X509Certificate>()
            if (certificates.isEmpty()) {
                throw IllegalArgumentException(
                    "Certificate chain for '$alias' contains no valid X509 certificates."
                )
            }

            // 4. 🔧 关键修复：显式指定 RSA_PKCS1_V15_WITH_SHA256 算法
            // 避免 apksig 在 Android + BouncyCastle jdk18on 环境下
            // 自动协商高级算法时触发 ASN.1 编码失败 (Failed to encode signature block)
            val signerConfig = ApkSigner.SignerConfig.Builder(
                "SIGNER",
                key,
                certificates
            )
                .setSignatureAlgorithm(ApkSigner.SignatureAlgorithm.RSA_PKCS1_V15_WITH_SHA256)
                .build()

            // 5. 执行签名（自动处理 ZipAlign、旧签名剥离、V1/V2/V3 块写入）
            ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(inputApk)
                .setOutputApk(outputApk)
                .setV1SigningEnabled(true)   // 兼容 Android < 7.0
                .setV2SigningEnabled(true)   // Android 7.0+ 强制要求
                .setV3SigningEnabled(true)   // Android 9.0+ 密钥轮换支持
                .setOtherSignersSignaturesPreserved(false) // 清除所有旧签名，防止格式冲突
                .build()
                .sign()

        } catch (e: Throwable) {
            // 安全提取最底层根因（类型为 Throwable，避免 Exception/Error 类型不匹配）
            val rootCause: Throwable = generateSequence(e) { it.cause }.lastOrNull() ?: e

            System.err.println("=== APK Sign Root Cause ===")
            System.err.println("Type: ${rootCause.javaClass.name}")
            System.err.println("Message: ${rootCause.message}")
            rootCause.printStackTrace(System.err)

            // 原样向上抛出，由 UI 层或 CI 日志面板捕获展示
            throw e
        }
    }
}
