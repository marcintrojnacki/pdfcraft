//! Signing with a PKCS #11 token, end to end, on SoftHSM (a software token): listing, PIN
//! handling, RSA and ECDSA keys, a key that wants its PIN for every signature, and a batch whose
//! signatures wait for each other as CloudSigner's transaction needs. Skipped when SoftHSM isn't
//! installed (`apt install softhsm2`, `brew install softhsm`); `PDFCRAFT_TEST_SOFTHSM` names the
//! library elsewhere.
//!
//! SoftHSM reads its token folder from `SOFTHSM2_CONF`, so the checks run in a child process
//! (this test binary again) with that set to a fresh folder.

#![cfg(not(target_arch = "wasm32"))]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use pdfcraft_cos::Document;
use pdfcraft_sign::keys::{DigestAlg, ExternalKey};
use pdfcraft_sign::pkcs11::{self, TokenIdentity, Transaction};
use pdfcraft_sign::{Certificate, Name, PrivateKey, PublicKey, SignError, SignOptions, Status, Time, TrustStore, der, signatures};

const PIN: &str = "123456";
const LABEL: &str = "PdfCraft test";

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
fn signs_with_a_softhsm_token() {
    let Some(lib) = softhsm() else {
        eprintln!("SoftHSM isn't installed: PKCS #11 signing not checked");
        return;
    };
    let dir = std::env::temp_dir().join(format!("pdfcraft-softhsm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    let conf = dir.join("softhsm2.conf");
    std::fs::write(&conf, format!("directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n", dir.join("tokens").display()))
        .unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "softhsm_checks", "--ignored", "--nocapture", "--test-threads=1"])
        .env("SOFTHSM2_CONF", &conf)
        .env("PDFCRAFT_TEST_SOFTHSM_LIB", &lib)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{text}");
    assert!(text.contains("1 passed"), "the checks ran: {text}");
}

/// Signs through a session the test holds (only to make the token's own certificates).
struct SetupKey {
    session: Mutex<Session>,
    key: ObjectHandle,
    rsa: bool,
    /// The key wants its PIN after every C_SignInit (CKA_ALWAYS_AUTHENTICATE).
    always: bool,
}

impl ExternalKey for SetupKey {
    fn sign(&self, alg: DigestAlg, msg: &[u8]) -> Result<Vec<u8>, SignError> {
        let session = self.session.lock().unwrap();
        let digest = alg.digest(&[msg]);
        if self.always {
            let ck = |e: CkError| SignError::Crypto(e.to_string());
            session.sign_init(&Mechanism::Sha256RsaPkcs, self.key).map_err(ck)?;
            session.login(UserType::ContextSpecific, Some(&AuthPin::from(PIN.to_string()))).map_err(ck)?;
            session.sign_update(msg).map_err(ck)?;
            return session.sign_final().map_err(ck);
        }
        if self.rsa {
            let info = der::seq(&[&der::algorithm(alg.oid(), Some(&der::null())), &der::octets(&digest)]);
            session.sign(&Mechanism::RsaPkcs, self.key, &info).map_err(|e| SignError::Crypto(e.to_string()))
        } else {
            let raw = session.sign(&Mechanism::Ecdsa, self.key, &digest).map_err(|e| SignError::Crypto(e.to_string()))?;
            PublicKey::P256(Vec::new()).store_signature_der(&raw)
        }
    }
}

/// A key pair generated on the token with a self-signed certificate stored beside it.
fn make_identity(session: Session, id: u8, cn: &str, rsa: bool, always_authenticate: bool) -> Session {
    let common = [Attribute::Token(true), Attribute::Id(vec![id]), Attribute::Label(cn.as_bytes().to_vec())];
    let mut public_t = common.to_vec();
    public_t.push(Attribute::Verify(true));
    let mut private_t = common.to_vec();
    private_t.extend([Attribute::Private(true), Attribute::Sensitive(true), Attribute::Sign(true)]);
    if always_authenticate {
        private_t.push(Attribute::AlwaysAuthenticate(true));
    }
    let (public, private) = if rsa {
        public_t.extend([Attribute::ModulusBits(2048.into()), Attribute::PublicExponent(vec![1, 0, 1])]);
        session.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public_t, &private_t).unwrap()
    } else {
        public_t.push(Attribute::EcParams(der::oid("1.2.840.10045.3.1.7")));
        session.generate_key_pair(&Mechanism::EccKeyPairGen, &public_t, &private_t).unwrap()
    };
    let public_key = if rsa {
        let a = session.get_attributes(public, &[AttributeType::Modulus, AttributeType::PublicExponent]).unwrap();
        let (mut n, mut e) = (Vec::new(), Vec::new());
        for a in a {
            match a {
                Attribute::Modulus(v) => n = v,
                Attribute::PublicExponent(v) => e = v,
                _ => {}
            }
        }
        PublicKey::Rsa { n, e }
    } else {
        let a = session.get_attributes(public, &[AttributeType::EcPoint]).unwrap();
        let Some(Attribute::EcPoint(point)) = a.into_iter().next() else { panic!("no EC point") };
        // CKA_EC_POINT is the point wrapped in a DER OCTET STRING.
        let point = der::Tlv::parse_all(&point).unwrap().value.to_vec();
        PublicKey::P256(point)
    };
    let session = Mutex::new(session);
    let key = PrivateKey::external(public_key, Arc::new(SetupKey { session, key: private, rsa, always: always_authenticate }));
    let name = Name::build(cn, "", "PdfCraft tests", "", "PL");
    let cert = Certificate::self_signed(&name, &key, Time::from_unix(1_767_225_600), 5, &[id]).unwrap();
    drop(key);
    // The session went into the key; open another to store the certificate.
    let ctx = Pkcs11::new(std::env::var_os("PDFCRAFT_TEST_SOFTHSM_LIB").unwrap()).unwrap();
    let _ = ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK));
    let slot = token_slot(&ctx);
    let session = ctx.open_rw_session(slot).unwrap();
    match session.login(UserType::User, Some(&AuthPin::from(PIN.to_string()))) {
        Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        Err(e) => panic!("{e}"),
    }
    session
        .create_object(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Token(true),
            Attribute::Id(vec![id]),
            Attribute::Label(cn.as_bytes().to_vec()),
            Attribute::Subject(cert.subject.raw.clone()),
            Attribute::Value(cert.raw.clone()),
        ])
        .unwrap();
    session
}

fn token_slot(ctx: &Pkcs11) -> cryptoki::slot::Slot {
    ctx.get_slots_with_token().unwrap().into_iter().find(|s| ctx.get_token_info(*s).is_ok_and(|i| i.label().trim() == LABEL)).expect("the test token")
}

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

fn open(b: &[u8]) -> Document {
    Document::open(Arc::new(b.to_vec())).unwrap()
}

fn opts(reason: &str) -> SignOptions {
    SignOptions { page: 0, reason: Some(reason.into()), date: "D:20261014120000+02'00'".into(), ..SignOptions::default() }
}

/// The document's signature, validated trusting the token's certificate.
fn check(signed: &[u8], id: &TokenIdentity) {
    let trust = TrustStore { certs: vec![id.certificate.clone()] };
    let s = signatures(&open(signed), signed, &trust).into_iter().find(|s| s.signed).expect("a signature");
    assert_eq!(s.status, Status::Valid, "{:?}", s.details);
    assert_eq!(s.signer.as_deref(), id.certificate.subject.common_name());
}

#[test]
#[ignore = "run by signs_with_a_softhsm_token with SoftHSM set up"]
fn softhsm_checks() {
    let Some(lib) = std::env::var_os("PDFCRAFT_TEST_SOFTHSM_LIB").map(PathBuf::from) else { return };
    // A fresh token with a user PIN, and three identities on it.
    let ctx = Pkcs11::new(&lib).unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).unwrap();
    let free = *ctx.get_slots_with_token().unwrap().first().unwrap();
    let so = AuthPin::from("so-secret".to_string());
    ctx.init_token(free, &so, LABEL).unwrap();
    let slot = token_slot(&ctx);
    let session = ctx.open_rw_session(slot).unwrap();
    session.login(UserType::So, Some(&so)).unwrap();
    session.init_pin(&AuthPin::from(PIN.to_string())).unwrap();
    session.logout().unwrap();
    session.login(UserType::User, Some(&AuthPin::from(PIN.to_string()))).unwrap();
    let session = make_identity(session, 1, "Token RSA", true, false);
    let session = make_identity(session, 2, "Token ECDSA", false, false);
    let session = make_identity(session, 3, "Token Always", true, true);
    session.logout().unwrap();
    drop(session);

    // Listed: each certificate with its key (private keys are hidden until login, so the
    // certificates are what tells them), and the PIN the token wants.
    let modules = vec![lib.clone()];
    let listing = pkcs11::list(&modules);
    assert!(listing.problems.is_empty(), "{:?}", listing.problems);
    // SoftHSM keeps objects in files named at random, so the order isn't fixed.
    let mut names: Vec<String> = listing.ids.iter().map(TokenIdentity::display_name).collect();
    names.sort();
    assert_eq!(names, ["Token Always (PdfCraft test)", "Token ECDSA (PdfCraft test)", "Token RSA (PdfCraft test)"]);
    assert!(listing.ids.iter().all(|i| i.needs_pin && i.module == lib));
    let named = |cn: &str| listing.ids.iter().find(|i| i.certificate.subject.common_name() == Some(cn)).unwrap().certificate.clone();
    let rsa = pkcs11::find(&modules, &pkcs11::reference(&named("Token RSA"))).unwrap();
    assert_eq!(rsa.certificate, named("Token RSA"));
    assert_eq!(pkcs11::find(&modules, "pkcs11:Token ECDSA").unwrap().certificate, named("Token ECDSA"));
    assert!(pkcs11::find(&modules, "pkcs11:nobody").is_err());

    // The PIN: missing, wrong, right.
    assert!(matches!(rsa.open(None), Err(SignError::Crypto(m)) if m.contains("needs its PIN")));
    assert!(matches!(rsa.open(Some("000000")), Err(SignError::WrongPassword)));

    // One document with each key; the always-authenticate key signs in parts, giving its PIN
    // again after C_SignInit.
    for id in &listing.ids {
        let digital_id = id.open(Some(PIN)).unwrap();
        assert!(digital_id.key.is_external());
        let signed = pdfcraft_sign::sign(&open(&fixture()), &digital_id, &opts("single")).unwrap();
        check(&signed, id);
    }

    // A batch: three documents sign together, each in its own session, once all three are at
    // their signing. One of them fails before it signs and must not hold the others back.
    let tx = Transaction::begin(&rsa, Some(PIN), 4).unwrap();
    let ids: Vec<_> = (0..4).map(|_| tx.digital_id().unwrap()).collect();
    assert!(tx.digital_id().is_err(), "a batch of four hands out four digital IDs");
    drop(tx);
    let (done, results) = std::sync::mpsc::channel();
    for (i, digital_id) in ids.into_iter().enumerate() {
        let done = done.clone();
        std::thread::spawn(move || {
            let mut o = opts(&format!("batch {i}"));
            if i == 2 {
                // A field that isn't there: this document ends before its signing.
                o.field = Some("Missing".into());
            }
            let r = pdfcraft_sign::sign(&open(&fixture()), &digital_id, &o);
            drop(digital_id);
            done.send((i, r)).unwrap();
        });
    }
    drop(done);
    let mut got: Vec<(usize, Result<Vec<u8>, SignError>)> =
        (0..4).map(|_| results.recv_timeout(Duration::from_secs(60)).expect("the batch finished")).collect();
    got.sort_by_key(|(i, _)| *i);
    for (i, r) in got {
        match (i, r) {
            (2, r) => assert!(r.is_err(), "document 2 has no field Missing"),
            (_, r) => check(&r.unwrap(), &rsa),
        }
    }
}
