package com.devtools.apksigner.core

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
            FileInputStream(keystoreFile).use { stream ->
                ks.load(stream, password)
            }

            if (!ks.containsAlias(alias)) {
                val availableAliases = ks.aliases().toList()
                throw IllegalArgumentException(
                    "Keystore does not contain alias '$alias'. Available aliases: $availableAliases"
                )
            }

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

            // 🔧 修复：移除已废弃的 setSignatureAlgorithm()
            // apksig 8.x 会根据密钥类型自动选择最优算法
            val signerConfig = ApkSigner.SignerConfig.Builder(
                "SIGNER",
                key,
                certificates
            ).build()

            ApkSigner.Builder(listOf(signerConfig))
                .setInputApk(inputApk)
                .setOutputApk(outputApk)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .setOtherSignersSignaturesPreserved(false)
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
