//! The PKCS #11 signing tools (sign_pkcs11_ids, sign_document and sign_documents with a pkcs11:
//! identity) on a SoftHSM token. Skipped when SoftHSM isn't installed (`apt install softhsm2`,
//! `brew install softhsm`); `PDFCRAFT_TEST_SOFTHSM` names the library elsewhere.
//!
//! SoftHSM reads its token folder from `SOFTHSM2_CONF` and the tools read their modules from
//! `PDFCRAFT_PKCS11_MODULES`, so the checks run in a child process (this test binary again).

#![cfg(not(target_arch = "wasm32"))]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use pdfcraft_automation::{Automation, Content, ToolError};
use pdfcraft_engine::sign::keys::{DigestAlg, ExternalKey};
use pdfcraft_engine::sign::{Certificate, Name, PrivateKey, PublicKey, SignError, Time, der};
use serde_json::{Value, json};

const PIN: &str = "246810";

fn softhsm() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("PDFCRAFT_TEST_SOFTHSM") {
        return Some(PathBuf::from(p));
    }
    [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.dylib",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}

#[test]
fn signing_tools_with_a_softhsm_token() {
    let Some(lib) = softhsm() else {
        eprintln!("SoftHSM isn't installed: the PKCS #11 signing tools not checked");
        return;
    };
    let dir = std::env::temp_dir().join(format!("pdfcraft-automation-softhsm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    let conf = dir.join("softhsm2.conf");
    std::fs::write(&conf, format!("directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n", dir.join("tokens").display()))
        .unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "softhsm_tool_checks", "--ignored", "--nocapture", "--test-threads=1"])
        .env("SOFTHSM2_CONF", &conf)
        .env("PDFCRAFT_PKCS11_MODULES", &lib)
        .env("PDFCRAFT_TEST_WORKDIR", &dir)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{text}");
    assert!(text.contains("1 passed"), "the checks ran: {text}");
}

/// Signs through a session the test holds (only to make the token's certificate).
struct SetupKey {
    session: Mutex<Session>,
    key: ObjectHandle,
}

impl ExternalKey for SetupKey {
    fn sign(&self, alg: DigestAlg, msg: &[u8]) -> Result<Vec<u8>, SignError> {
        let info = der::seq(&[&der::algorithm(alg.oid(), Some(&der::null())), &der::octets(&alg.digest(&[msg]))]);
        self.session.lock().unwrap().sign(&Mechanism::RsaPkcs, self.key, &info).map_err(|e| SignError::Crypto(e.to_string()))
    }
}

/// A token holding one RSA identity, "Token Signer"; returns its certificate.
fn set_up_token(lib: &std::path::Path) -> Certificate {
    let ctx = Pkcs11::new(lib).unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).unwrap();
    let free = *ctx.get_slots_with_token().unwrap().first().unwrap();
    let so = AuthPin::from("so-secret".to_string());
    ctx.init_token(free, &so, "Tools test").unwrap();
    let slot =
        ctx.get_slots_with_token().unwrap().into_iter().find(|s| ctx.get_token_info(*s).is_ok_and(|i| i.label().trim() == "Tools test")).unwrap();
    let session = ctx.open_rw_session(slot).unwrap();
    session.login(UserType::So, Some(&so)).unwrap();
    session.init_pin(&AuthPin::from(PIN.to_string())).unwrap();
    session.logout().unwrap();
    session.login(UserType::User, Some(&AuthPin::from(PIN.to_string()))).unwrap();
    // A second session keeps the token logged in after the first goes into the setup key.
    let keeper = ctx.open_rw_session(slot).unwrap();
    let common = [Attribute::Token(true), Attribute::Id(vec![7])];
    let mut public_t = common.to_vec();
    public_t.extend([Attribute::Verify(true), Attribute::ModulusBits(2048.into()), Attribute::PublicExponent(vec![1, 0, 1])]);
    let mut private_t = common.to_vec();
    private_t.extend([Attribute::Private(true), Attribute::Sensitive(true), Attribute::Sign(true)]);
    let (public, private) = session.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public_t, &private_t).unwrap();
    let (mut n, mut e) = (Vec::new(), Vec::new());
    for a in session.get_attributes(public, &[AttributeType::Modulus, AttributeType::PublicExponent]).unwrap() {
        match a {
            Attribute::Modulus(v) => n = v,
            Attribute::PublicExponent(v) => e = v,
            _ => {}
        }
    }
    let key = PrivateKey::external(PublicKey::Rsa { n, e }, Arc::new(SetupKey { session: Mutex::new(session), key: private }));
    let cert = Certificate::self_signed(&Name::build("Token Signer", "", "PdfCraft tests", "", "PL"), &key, Time::from_unix(1_767_225_600), 5, &[7])
        .unwrap();
    drop(key);
    keeper
        .create_object(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Token(true),
            Attribute::Id(vec![7]),
            Attribute::Subject(cert.subject.raw.clone()),
            Attribute::Value(cert.raw.clone()),
        ])
        .unwrap();
    keeper.logout().unwrap();
    cert
}

/// A one-page PDF.
fn fixture() -> Vec<u8> {
    let objs: [&[u8]; 4] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Contents 4 0 R >>",
        b"<< /Length 0 >>\nstream\n\nendstream",
    ];
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(o);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    out
}

fn ok(a: &mut Automation, tool: &str, args: Value) -> Value {
    match a.call(tool, &args) {
        Ok(mut c) => match c.remove(0) {
            Content::Json(v) => v,
            other => panic!("{tool}: expected JSON, got {other:?}"),
        },
        Err(e) => panic!("{tool} {args}: {e}"),
    }
}

#[test]
#[ignore = "run by signing_tools_with_a_softhsm_token with SoftHSM set up"]
fn softhsm_tool_checks() {
    let (Some(lib), Some(dir)) = (std::env::var_os("PDFCRAFT_PKCS11_MODULES"), std::env::var_os("PDFCRAFT_TEST_WORKDIR")) else { return };
    let (lib, dir) = (PathBuf::from(lib), PathBuf::from(dir));
    let cert = set_up_token(&lib);
    for name in ["a", "b", "c", "d"] {
        std::fs::write(dir.join(format!("{name}.pdf")), fixture()).unwrap();
    }
    let mut a = Automation::new().with_root(&dir).unwrap().with_clock(|| 1_790_000_000);

    let listed = ok(&mut a, "sign_pkcs11_ids", json!({}));
    assert_eq!(listed["count"], 1, "{listed}");
    let id = &listed["ids"][0];
    assert_eq!(id["name"], "Token Signer (Tools test)");
    assert_eq!(id["needs_pin"], true);
    assert_eq!(id["certificate"]["sha256"], cert.fingerprint());
    let reference = id["id"].as_str().unwrap().to_string();
    assert!(reference.starts_with("pkcs11:"));

    let docs: Vec<u64> =
        ["a", "b", "c", "d"].iter().map(|n| ok(&mut a, "doc_open", json!({ "path": format!("{n}.pdf") }))["doc"].as_u64().unwrap()).collect();
    // A wrong PIN is the caller's to fix.
    let wrong = a.call("sign_document", &json!({ "doc": docs[0], "id": reference, "password": "000000", "out": "x.pdf" }));
    assert!(matches!(wrong, Err(ToolError::InvalidArgs(m)) if m.contains("PIN")));
    // By common name, one document.
    let one = ok(&mut a, "sign_document", json!({ "doc": docs[0], "id": "pkcs11:Token Signer", "password": PIN, "out": "a-signed.pdf" }));
    assert_eq!(one["signature"]["signer"], "Token Signer");
    assert_ne!(one["signature"]["status"], "invalid", "{one}");

    // Three documents in one transaction; the third names a field that isn't there and fails
    // alone. The same document twice is refused before anything is signed.
    let twice = a.call(
        "sign_documents",
        &json!({ "id": reference, "password": PIN, "documents": [{ "doc": docs[1], "out": "1.pdf" }, { "doc": docs[1], "out": "2.pdf" }] }),
    );
    assert!(matches!(twice, Err(ToolError::InvalidArgs(_))));
    let batch = ok(
        &mut a,
        "sign_documents",
        json!({
            "id": reference,
            "password": PIN,
            "documents": [
                { "doc": docs[1], "out": "b-signed.pdf", "reason": "batch" },
                { "doc": docs[2], "out": "c-signed.pdf", "page": 1, "rect": [20, 20, 220, 80] },
                { "doc": docs[3], "out": "d-signed.pdf", "field": "Missing" },
            ],
        }),
    );
    assert_eq!((batch["count"].as_u64(), batch["signed"].as_u64(), batch["transactions"].as_u64()), (Some(3), Some(2), Some(1)), "{batch}");
    let entries = batch["documents"].as_array().unwrap();
    for (entry, out) in entries.iter().zip(["b-signed.pdf", "c-signed.pdf"]) {
        assert_eq!(entry["result"]["signature"]["signer"], "Token Signer", "{entry}");
        assert_ne!(entry["result"]["signature"]["status"], "invalid", "{entry}");
        assert!(dir.join(out).is_file());
    }
    assert_eq!(entries[1]["result"]["signature"]["visible"], true);
    assert!(entries[2]["error"].as_str().is_some_and(|e| !e.is_empty()), "{}", entries[2]);
    assert!(!dir.join("d-signed.pdf").exists());
    // The signed documents now show their signatures.
    assert_eq!(ok(&mut a, "sign_list", json!({ "doc": docs[1] }))["signed"], 1);
}
