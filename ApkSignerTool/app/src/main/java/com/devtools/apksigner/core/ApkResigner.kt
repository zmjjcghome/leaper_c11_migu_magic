package com.devtools.apksigner.core

import com.android.apksig.ApkSigner
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
// core/ApkResigner.kt
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
            
            val key = ks.getKey(alias, password)
            if (key !is PrivateKey) {
                throw IllegalArgumentException(
                    "Entry '$alias' is not a private key (type: ${key?.javaClass?.name})"
                )
            }
            
            val cert = ks.getCertificate(alias) as X509Certificate
            val signerConfig = ApkSigner.SignerConfig.Builder("SIGNER", key, listOf(cert)).build()

            ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(inputApk)
                .setOutputApk(outputApk)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .build()
                .sign()
                
        } catch (e: Throwable) { // 🔧 改为捕获 Throwable 而非 Exception
            // 安全地获取最底层的根因（类型为 Throwable）
            val rootCause: Throwable = generateSequence(e) { it.cause }.lastOrNull() ?: e
            
            System.err.println("=== APK Sign Root Cause ===")
            System.err.println("Type: ${rootCause.javaClass.name}")
            System.err.println("Message: ${rootCause.message}")
            rootCause.printStackTrace(System.err)
            
            // 如果原始异常是 Exception，则原样抛出；如果是 Error，也向上传播
            throw e
        }
    }
}
