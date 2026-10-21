plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.devtools.apksigner"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.devtools.apksigner"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    signingConfigs {
        create("release") {
            storeFile = file("$rootDir/app/release-key.jks")
            storePassword = System.getenv("RELEASE_KEYSTORE_PASSWORD")
            keyAlias = System.getenv("RELEASE_KEY_ALIAS")
            keyPassword = System.getenv("RELEASE_KEY_PASSWORD")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            signingConfig = signingConfigs.getByName("release")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    
    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.8"
    }

    packaging {
        resources {
            // 排除 BouncyCastle 多版本 JAR 中冲突的 OSGI 清单文件
            excludes += setOf(
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                "META-INF/versions/11/OSGI-INF/MANIFEST.MF", // 预防性排除 Java 11 版本
                "META-INF/DEPENDENCIES",                    // 预防其他常见 META-INF 冲突
                "META-INF/LICENSE.md",
                "META-INF/NOTICE.md"
            )
        }
    }

}

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.0.4")
    
    // BouncyCastle: 生成标准证书 (使用 jdk18on 避免与 Android 系统自带老版本冲突)
    implementation("org.bouncycastle:bcprov-jdk18on:1.78")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78")
    
    // apksig: Google 官方 APK 签名库
    implementation("com.android.tools.build:apksig:8.2.2")
    
    // Compose UI
    implementation(platform("androidx.compose:compose-bom:2024.02.00"))
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.navigation:navigation-compose:2.7.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.7.0")
}
