package com.devtools.apksigner.core

import com.android.apksig.ApkSigner
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
// // core/ApkResigner.kt
import com.android.apksig.ApkSigner
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

object ApkResigner {
    fun resign(
        inputApk: File,
        outputApk: File,
        keystoreFile: File,
        password: CharArray,
        alias: String
    ) {
        try {
            val ks = KeyStore.getInstance("PKCS12")
            FileInputStream(keystoreFile).use { ks.load(it, password) }

            if (!ks.containsAlias(alias)) {
                throw IllegalArgumentException(
                    "Keystore does not contain alias: $alias. Available: ${ks.aliases().toList()}"
                )
            }

            val key = ks.getKey(alias, password) as? PrivateKey
                ?: throw IllegalArgumentException("Entry '$alias' is not a private key")
            val cert = ks.getCertificate(alias) as? X509Certificate
                ?: throw IllegalArgumentException("Entry '$alias' has no certificate")

            // 🔧 关键修复：显式指定签名算法，避免 Provider 自动协商失败
            // apksig 会根据此算法名选择最合适的内部编码器
            val signerConfig = ApkSigner.SignerConfig.Builder(
                "SIGNER",
                key,
                listOf(cert)
            )
                .setSignatureAlgorithm(ApkSigner.SignatureAlgorithm.RSA_PKCS1_V15_WITH_SHA256) // 显式指定
                .build()

            ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(inputApk)
                .setOutputApk(outputApk)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .setOtherSignersSignaturesPreserved(false) // 确保清除旧签名
                .build()
                .sign()

        } catch (e: Throwable) {
            val rootCause: Throwable = generateSequence(e) { it.cause }.lastOrNull() ?: e
            System.err.println("=== APK Sign Root Cause ===")
            System.err.println("Type: ${rootCause.javaClass.name}")
            System.err.println("Message: ${rootCause.message}")
            rootCause.printStackTrace(System.err)
            throw e
        }
    }
}
