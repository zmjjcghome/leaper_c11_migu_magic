package com.devtools.apksigner.core

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Date

object KeystoreGenerator {
    fun generate(
        outputFile: File,
        alias: String,
        password: CharArray,
        validityYears: Int = 25
    ) {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandom())
        val keyPair = kpg.generateKeyPair()

        val issuer = X500Name("CN=Android DevTools, O=Dev, C=CN")
        val serial = BigInteger.valueOf(System.currentTimeMillis())
        val notBefore = Date()
        val notAfter = Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000 * validityYears)

        val certBuilder = JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, issuer, keyPair.public)
        val signer = JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.private)
        val certHolder = certBuilder.build(signer)
        
        // 使用 PKCS12 格式，兼容性最好
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, password)
        ks.setKeyEntry(alias, keyPair.private, password, arrayOf(certHolder.toASN1Structure().encoded.let { 
            java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(it.inputStream()) 
        }))

        FileOutputStream(outputFile).use { ks.store(it, password) }
    }
}
