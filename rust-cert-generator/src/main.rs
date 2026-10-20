use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, KeyUsagePurpose, ExtendedKeyUsagePurpose};
use p12_keystore::{KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain, Certificate};
use time::{OffsetDateTime, Duration};
use std::env;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 获取传入的输出目录参数，默认为当前目录
    let args: Vec<String> = env::args().collect();
    let out_dir = if args.len() > 1 { &args[1] } else { "." };
    fs::create_dir_all(out_dir)?;

    // 2. 配置证书参数
    let mut params = CertificateParams::default();
    
    // 设置证书主题信息 (Subject DN)
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Android Debug");
    dn.push(DnType::OrganizationName, "My Android App");
    dn.push(DnType::CountryName, "CN");
    params.distinguished_name = dn;

    // 设置证书有效期 (10年)
    params.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(365 * 10);

    // 设置密钥用途 (用于代码签名)
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];

    // 3. 生成自签名证书和密钥对
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    // 4. 构建 PKCS#12 密钥库
    let p12_key = PrivateKey::from_der(&key_pair.serialize_der())?;
    let p12_cert = Certificate::from_der(cert.der())?;
    
    let chain = PrivateKeyChain::new(
        b"android-key".to_vec(), 
        p12_key, 
        vec![p12_cert]
    );
    
    let friendly_name = "my-key-alias"; 
    let mut keystore = KeyStore::new();
    keystore.add_entry(friendly_name, KeyStoreEntry::PrivateKeyChain(chain));

    // 5. 导出为 .p12 文件并保存到指定输出目录
    let p12_password = "android_keystore_password"; 
    let p12_bytes = keystore.writer(p12_password).write()?;
    
    let p12_path = Path::new(out_dir).join("android_release.p12");
    fs::write(&p12_path, p12_bytes)?;
    println!("✅ 成功生成 Android 签名证书: {}", p12_path.display());

    Ok(())
}
