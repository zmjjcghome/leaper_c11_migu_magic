use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, KeyUsagePurpose, ExtendedKeyUsagePurpose};
use p12_keystore::{KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain, Certificate};
use time::{OffsetDateTime, Duration};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 配置证书参数
    let mut params = CertificateParams::default();
    
    // 设置证书主题信息 (Subject DN)
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Android Debug");
    dn.push(DnType::OrganizationName, "My Android App");
    dn.push(DnType::CountryName, "CN");
    params.distinguished_name = dn;

    // 设置证书有效期 (例如：10年)
    params.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365 * 10);

    // 设置密钥用途 (用于代码签名)
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];

    // 2. 生成自签名证书和密钥对
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    // 3. 构建 PKCS#12 密钥库
    // 修复 E0061: PrivateKeyChain::new 需要 3 个参数: (key_id, private_key, certificates)
    let p12_key = PrivateKey::from_der(&key_pair.serialize_der())?;
    let p12_cert = Certificate::from_der(cert.der())?;
    
    // 使用一个唯一的 key-id，这里简单使用 "android-key"
    let chain = PrivateKeyChain::new(
        b"android-key".to_vec(), 
        p12_key, 
        vec![p12_cert]
    );
    
    // 4. 将证书链添加到 KeyStore
    // 修复 E0308: add_entry 的第一个参数需要 &str，而不是 String
    let friendly_name = "my-key-alias"; 
    let mut keystore = KeyStore::new();
    keystore.add_entry(friendly_name, KeyStoreEntry::PrivateKeyChain(chain));

    // 5. 导出为 .p12 文件
    let p12_password = "android_keystore_password"; 
    let p12_bytes = keystore.writer(p12_password).write()?;
    
    fs::write("android_release.p12", p12_bytes)?;
    println!("✅ 成功生成 Android 签名证书: android_release.p12");

    Ok(())
}
