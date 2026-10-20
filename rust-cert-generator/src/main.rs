use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, KeyUsagePurpose, ExtendedKeyUsagePurpose};
use p12-keystore::{KeyStore, KeyStoreEntry, PrivateKeyChain};
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
    
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "AutoSign");
    dn.push(DnType::OrganizationName, "AutoSign");
    dn.push(DnType::OrganizationalUnitName, "Dev");
    dn.push(DnType::CountryName, "CN");
    params.distinguished_name = dn;

    // 有效期 30 年 (10950天)
    params.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(10950);

    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::CodeSigning,
    ];

    // 3. 生成自签名证书和密钥对
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    // 4. 构建 PKCS#12 密钥库
    let mut keystore = KeyStore::new();
    let mut chain = PrivateKeyChain::new(key_pair.serialize_der());
    chain.add_certificate(cert.der().to_vec());
    
    let friendly_name = "autosign_alias".to_string();
    keystore.add_entry(friendly_name, KeyStoreEntry::PrivateKeyChain(chain));

    // 5. 导出为 .p12 文件（固定密码为 changeit，与原 Java 保持一致）
    let p12_password = "changeit";
    let p12_bytes = keystore.writer(p12_password).write()?;
    
    let p12_path = Path::new(out_dir).join("autosign.p12");
    fs::write(&p12_path, p12_bytes)?;
    
    println!("✅ 成功生成 P12 签名证书: {}", p12_path.display());

    Ok(())
}
