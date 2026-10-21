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
            
            // ⚠️ 关键检查点：验证别名和密码是否正确
            if (!ks.containsAlias(alias)) {
                throw IllegalArgumentException("Keystore does not contain alias: $alias. Available aliases: ${ks.aliases().toList()}")
            }
            
            val key = ks.getKey(alias, password)
            if (key !is PrivateKey) {
                throw IllegalArgumentException("Entry '$alias' is not a private key (type: ${key?.javaClass?.name}). It might be a trustedCertEntry instead of a privateKeyEntry.")
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
                
        } catch (e: Exception) {
            // 🔥 必须打印 cause，这才是真正的错误原因
            val rootCause = generateSequence(e) { it.cause }.lastOrNull()
            System.err.println("=== APK Sign Root Cause ===")
            rootCause?.printStackTrace()
            throw e // 重新抛出，保持原有行为
        }
    }
}
