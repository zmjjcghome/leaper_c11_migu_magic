use rcgen::{CertificateParams, DnType, KeyPair, PKCS_RSA_SHA256};
use time::{Duration, OffsetDateTime};
use std::env;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 获取传入的输出目录参数，默认为当前目录
    let args: Vec<String> = env::args().collect();
    let out_dir = if args.len() > 1 { &args[1] } else { "." };
    fs::create_dir_all(out_dir)?;

    // 2. 配置自签名证书参数（30年有效期，CN=AutoSign）
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "AutoSign");
    params.distinguished_name.push(DnType::OrganizationName, "AutoSign");
    params.distinguished_name.push(DnType::OrganizationalUnitName, "Dev");
    params.distinguished_name.push(DnType::CountryName, "CN");

    let not_before = OffsetDateTime::now_utc() - Duration::days(1);
    let not_after = not_before + Duration::days(10950); // 约30年
    params.not_before = not_before;
    params.not_after = not_after;

    // 3. 生成 RSA 2048 密钥对并签发证书
    let key_pair = KeyPair::generate_for(&PKCS_RSA_SHA256)?;
    let cert = params.signed_by(&key_pair, &key_pair)?;

    // 4. 导出为标准 DER 格式文件
    let key_path = Path::new(out_dir).join("private_key.der");
    let cert_path = Path::new(out_dir).join("cert.der");

    fs::write(&key_path, key_pair.serialize_der())?;
    fs::write(&cert_path, cert.der())?;

    println!("Successfully generated DER private key and certificate in {}", out_dir);
    Ok(())
}
