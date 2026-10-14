//! Signature tools: list and validate signatures, create a self-signed digital ID, sign a
//! document, and manage trusted certificates. Rectangles are points from the top-left of the
//! displayed page.

use std::path::PathBuf;
use std::sync::Arc;

use pdfcraft_engine::sign::{self, Certificate, DigitalId, Modification, Name, PrivateKey};
use pdfcraft_engine::{DocId, SignOptions, SignatureInfo, SignatureStatus};
use serde_json::{Value, json};

use crate::{Args, Automation, Result, ToolError, failed, write_atomic};

fn bad(m: impl Into<String>) -> ToolError {
    ToolError::InvalidArgs(m.into())
}

/// The PKCS #11 modules the tools may load: those in `PDFCRAFT_PKCS11_MODULES` (a list of library
/// paths, written as PATH is) and CloudSigner where its installer puts it. A module is code loaded
/// into the process, so the user chooses them; a tool's arguments never name one.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn pkcs11_modules() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::env::var_os("PDFCRAFT_PKCS11_MODULES")
        .map(|v| std::env::split_paths(&v).filter(|p| !p.as_os_str().is_empty()).collect())
        .unwrap_or_default();
    for m in sign::pkcs11::known_modules() {
        if !out.contains(&m) {
            out.push(m);
        }
    }
    out
}

/// A token's refusal of its PIN is the caller's to fix; other failures are the tool's.
#[cfg(not(target_arch = "wasm32"))]
fn token_error(e: sign::SignError) -> ToolError {
    match e {
        sign::SignError::WrongPassword => bad("the token's PIN is incorrect"),
        e => failed(e),
    }
}

/// A signing error: a graphic the signer refuses is the caller's to fix.
fn sign_error(e: pdfcraft_engine::EditError) -> ToolError {
    match e {
        pdfcraft_engine::EditError::Sign(m) if m.starts_with("the signature graphic") => bad(m),
        e => failed(e),
    }
}

/// Seconds since 1970 → a DER time.
fn time(secs: i64) -> sign::Time {
    sign::Time::from_unix(secs)
}

pub(crate) fn cert_json(c: &Certificate) -> Value {
    json!({
        "name": c.display_name(),
        "subject": c.subject.display(),
        "issuer": c.issuer.display(),
        "email": c.subject.email(),
        "serial": c.serial_hex(),
        "valid_from": c.not_before.to_string(),
        "valid_to": c.not_after.to_string(),
        "key": c.public_key.describe(),
        "self_signed": c.is_self_signed(),
        "sha256": c.fingerprint(),
    })
}

impl Automation {
    fn sig_json(&self, a: &Args, s: &SignatureInfo) -> Result<Value> {
        let doc = self.doc(a)?;
        let rect = match (s.page, s.rect) {
            (Some(p), Some(r)) if s.visible => doc.info.pages.get(p).map(|pi| {
                let (a0, a1) = (pi.user_to_view(r[0] as f32, r[3] as f32), pi.user_to_view(r[2] as f32, r[1] as f32));
                json!([a0[0].min(a1[0]), a0[1].min(a1[1]), a0[0].max(a1[0]), a0[1].max(a1[1])])
            }),
            _ => None,
        };
        let (modification, changes) = match &s.modification {
            Modification::None => ("none", Vec::new()),
            Modification::Allowed(c) => ("allowed", c.clone()),
            Modification::Disallowed(c) => ("disallowed", c.clone()),
        };
        Ok(json!({
            "field": s.field,
            "signed": s.signed,
            "status": if !s.signed { "unsigned" } else { match s.status { SignatureStatus::Valid => "valid", SignatureStatus::Unknown => "unknown", SignatureStatus::Invalid => "invalid" } },
            "summary": s.summary(),
            "signer": s.signer,
            "certificate": s.certificate.as_ref().map(cert_json),
            "chain": s.chain.iter().skip(1).map(cert_json).collect::<Vec<_>>(),
            "date": s.date,
            "reason": s.reason,
            "location": s.location,
            "contact": s.contact,
            "certify": s.certify,
            "page": s.page.map(|p| p + 1),
            "rect": rect,
            "visible": s.visible,
            "revision": s.revision,
            "sub_filter": s.sub_filter,
            "algorithm": s.algorithm,
            "timestamp": s.timestamp,
            "timestamp_time": s.timestamp_time.map(|t| t.to_string()),
            "modification": modification,
            "changes": changes,
            // Scripts read this, so the sentences stay in English, whatever the interface reads in.
            "details": s.details.iter().map(|d| d.message.clone()).collect::<Vec<_>>(),
        }))
    }

    pub(crate) fn sign_list(&self, a: &Args) -> Result<Value> {
        let doc = self.doc(a)?;
        let list: Vec<Value> = doc.signatures.iter().map(|s| self.sig_json(a, s)).collect::<Result<_>>()?;
        let signed = doc.signatures.iter().filter(|s| s.signed).count();
        let all_valid = signed > 0 && doc.signatures.iter().filter(|s| s.signed).all(|s| s.status == SignatureStatus::Valid);
        Ok(json!({ "count": list.len(), "signed": signed, "all_valid": all_valid, "signatures": list }))
    }

    pub(crate) fn sign_id_create(&mut self, a: &Args) -> Result<Value> {
        let name = a.str("name")?.trim().to_string();
        if name.is_empty() {
            return Err(bad("name must not be empty"));
        }
        let password = a.str("password")?;
        if password.chars().count() < 6 {
            return Err(bad("the password must have at least 6 characters"));
        }
        let path = self.resolve(a.str("path")?, true)?;
        let key = match a.opt_str("key")?.unwrap_or("rsa2048") {
            "rsa2048" => PrivateKey::generate_rsa(2048),
            "rsa3072" => PrivateKey::generate_rsa(3072),
            "rsa4096" => PrivateKey::generate_rsa(4096),
            "p256" => PrivateKey::generate_p256(),
            other => return Err(bad(format!("unknown key {other:?} (rsa2048, rsa3072, rsa4096, p256)"))),
        }
        .map_err(failed)?;
        let dn = Name::build(
            &name,
            a.opt_str("unit")?.unwrap_or(""),
            a.opt_str("organization")?.unwrap_or(""),
            a.opt_str("email")?.unwrap_or(""),
            a.opt_str("country")?.unwrap_or(""),
        );
        let years = a.opt_int("years")?.unwrap_or(5).clamp(1, 50) as u32;
        let now = self.session.now_secs();
        let serial = sign::keys::DigestAlg::Sha256.digest(&[name.as_bytes(), &now.to_be_bytes()])[..8].to_vec();
        let cert = Certificate::self_signed(&dn, &key, time(now), years, &serial).map_err(failed)?;
        let id = DigitalId { key, certificate: cert, chain: Vec::new(), friendly_name: Some(name) };
        let p12 = sign::pkcs12::write(&id, password).map_err(failed)?;
        write_atomic(&path, &p12)?;
        Ok(json!({ "path": path.to_string_lossy(), "certificate": cert_json(&id.certificate) }))
    }

    fn open_id(&self, a: &Args) -> Result<DigitalId> {
        // A macOS Keychain identity: "keychain:<fingerprint>" or "keychain:<common name>".
        if let Some(r) = a.str("id")?.strip_prefix("keychain:") {
            #[cfg(target_os = "macos")]
            return sign::keychain::find(&format!("keychain:{r}")).map_err(failed);
            #[cfg(not(target_os = "macos"))]
            return Err(failed(format!("keychain:{r}: Keychain identities are only available on macOS")));
        }
        if let Some(r) = a.str("id")?.strip_prefix("windows:") {
            #[cfg(target_os = "windows")]
            return sign::windows::find(&format!("windows:{r}")).map_err(failed);
            #[cfg(not(target_os = "windows"))]
            return Err(failed(format!("windows:{r}: Windows certificate store identities are only available on Windows")));
        }
        // A PKCS #11 token identity: "pkcs11:<fingerprint>" or "pkcs11:<common name>"; `password`
        // is the token's PIN when it wants one.
        if let Some(r) = a.str("id")?.strip_prefix("pkcs11:") {
            #[cfg(not(target_arch = "wasm32"))]
            return sign::pkcs11::find(&pkcs11_modules(), &format!("pkcs11:{r}")).map_err(failed)?.open(a.opt_str("password")?).map_err(token_error);
            #[cfg(target_arch = "wasm32")]
            return Err(failed(format!("pkcs11:{r}: PKCS #11 tokens aren't available in the browser")));
        }
        let path = self.resolve(a.str("id")?, false)?;
        let bytes = std::fs::read(&path).map_err(|e| failed(format!("{}: {e}", path.display())))?;
        sign::pkcs12::open(&bytes, a.opt_str("password")?.unwrap_or("")).map_err(|e| match e {
            sign::SignError::WrongPassword => bad("the digital ID password is incorrect"),
            e => failed(e),
        })
    }

    pub(crate) fn sign_document(&mut self, a: &Args) -> Result<Value> {
        let id = self.open_id(a)?;
        let (doc_id, opts, out) = self.sign_job(a)?;
        let signed = self.session.sign(doc_id, &id, opts).map_err(sign_error)?;
        self.save_signed(a, doc_id, &out, signed)
    }

    /// One document's signing: what to sign (`doc`, `field` or `page` and `rect`, `certify`,
    /// `graphic`, `reason`, `location`, `contact`) and where the signed file goes (`out`).
    fn sign_job(&self, a: &Args) -> Result<(DocId, SignOptions, PathBuf)> {
        let doc = self.doc(a)?;
        let doc_id = doc.id;
        let field = a.opt_str("field")?.map(str::to_string);
        let page = match a.opt_int("page")? {
            Some(p) if p >= 1 && (p as usize) <= doc.info.pages.len() => p as usize - 1,
            Some(p) => return Err(bad(format!("page {p} does not exist"))),
            None => 0,
        };
        let rect = match a.nums::<4>("rect")? {
            Some(r) => {
                let p = &doc.info.pages[page];
                let (u0, u1) = (p.view_to_user(r[0] as f32, r[1] as f32), p.view_to_user(r[2] as f32, r[3] as f32));
                let u = [u0[0].min(u1[0]) as f64, u0[1].min(u1[1]) as f64, u0[0].max(u1[0]) as f64, u0[1].max(u1[1]) as f64];
                if u[2] - u[0] < 4.0 || u[3] - u[1] < 4.0 {
                    return Err(bad("the signature rectangle is too small"));
                }
                Some(u)
            }
            None => None,
        };
        let certify = match a.get("certify") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(match s.as_str() {
                "no_changes" => 1,
                "form_fill" => 2,
                "comments" => 3,
                other => return Err(bad(format!("unknown certify level {other:?} (no_changes, form_fill, comments)"))),
            }),
            Some(v) => Some(v.as_u64().filter(|n| (1..=3).contains(n)).ok_or_else(|| bad("certify must be 1, 2 or 3"))? as u8),
        };
        let graphic = match a.get("graphic") {
            None | Some(Value::Null) => None,
            Some(g) if rect.is_none() && field.is_none() => return Err(bad(format!("graphic {g} needs a visible signature: pass rect or field"))),
            Some(g) => Some(self.signature_graphic(g)?),
        };
        let out = self.resolve(a.str("out")?, true)?;
        let opts = SignOptions {
            field,
            page,
            rect,
            reason: a.opt_str("reason")?.map(str::to_string),
            location: a.opt_str("location")?.map(str::to_string),
            contact: a.opt_str("contact")?.map(str::to_string),
            certify,
            graphic,
            ..SignOptions::default()
        };
        Ok((doc_id, opts, out))
    }

    /// Save a signed document to `out`, show it in the session, and describe its new signature.
    fn save_signed(&mut self, a: &Args, doc_id: DocId, out: &std::path::Path, signed: Arc<Vec<u8>>) -> Result<Value> {
        write_atomic(out, &signed)?;
        let path = out.to_string_lossy().into_owned();
        self.session.mark_signed(doc_id, signed.clone(), Some(path.clone())).map_err(failed)?;
        let doc = self.doc(a)?;
        let newest = doc.signatures.iter().filter(|s| s.signed).max_by_key(|s| s.revision).cloned();
        Ok(json!({ "path": path, "bytes": signed.len(), "signature": newest.map(|s| self.sig_json(a, &s)).transpose()? }))
    }

    /// Sign several documents with one digital ID. With a PKCS #11 token the signatures of up to
    /// 20 documents are made together, so CloudSigner (mSzafir) asks for one approval for them all;
    /// a document that fails doesn't stop the others.
    pub(crate) fn sign_documents(&mut self, a: &Args) -> Result<Value> {
        let jobs = a.get("documents").and_then(Value::as_array).ok_or_else(|| bad("documents must be an array of documents to sign"))?;
        if jobs.is_empty() || jobs.len() > 1000 {
            return Err(bad("documents must list 1 to 1000 documents"));
        }
        let parsed = jobs.iter().map(|j| self.sign_job(&Args(j))).collect::<Result<Vec<_>>>()?;
        for (i, (doc, _, out)) in parsed.iter().enumerate() {
            if parsed.iter().take(i).any(|(d, _, o)| d == doc || o == out) {
                return Err(bad("each document, and each out file, may appear once"));
            }
        }
        let reference = a.str("id")?;
        let mut transactions = 0;
        let results: Vec<std::result::Result<Arc<Vec<u8>>, pdfcraft_engine::EditError>> = if reference.starts_with("pkcs11:") {
            #[cfg(not(target_arch = "wasm32"))]
            {
                let identity = sign::pkcs11::find(&pkcs11_modules(), reference).map_err(failed)?;
                let pin = a.opt_str("password")?;
                let mut results = Vec::with_capacity(parsed.len());
                for chunk in parsed.chunks(sign::pkcs11::MAX_PER_TRANSACTION) {
                    let tx = sign::pkcs11::Transaction::begin(&identity, pin, chunk.len()).map_err(token_error)?;
                    let mut batch = Vec::with_capacity(chunk.len());
                    for (doc, opts, _) in chunk {
                        batch.push((*doc, tx.digital_id().map_err(failed)?, opts.clone()));
                    }
                    drop(tx);
                    transactions += 1;
                    results.extend(self.session.sign_together(batch));
                }
                results
            }
            #[cfg(target_arch = "wasm32")]
            return Err(failed(format!("{reference}: PKCS #11 tokens aren't available in the browser")));
        } else {
            let id = self.open_id(a)?;
            parsed.iter().map(|(doc, opts, _)| self.session.sign(*doc, &id, opts.clone())).collect()
        };
        let mut documents = Vec::with_capacity(parsed.len());
        let mut signed_count = 0;
        for ((job, (doc_id, _, out)), result) in jobs.iter().zip(&parsed).zip(results) {
            let entry = match result.map_err(sign_error).and_then(|signed| self.save_signed(&Args(job), *doc_id, out, signed)) {
                Ok(v) => {
                    signed_count += 1;
                    json!({ "doc": doc_id.0, "result": v })
                }
                Err(e) => json!({ "doc": doc_id.0, "error": e.to_string() }),
            };
            documents.push(entry);
        }
        Ok(json!({ "count": parsed.len(), "signed": signed_count, "transactions": transactions, "documents": documents }))
    }

    /// The signing identities on the PKCS #11 tokens of the modules the tools may load.
    pub(crate) fn sign_pkcs11_ids(&self) -> Result<Value> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let modules = pkcs11_modules();
            let listing = sign::pkcs11::list(&modules);
            let ids: Vec<Value> = listing
                .ids
                .iter()
                .map(|id| {
                    json!({
                        "id": sign::pkcs11::reference(&id.certificate),
                        "name": id.display_name(),
                        "token": id.token,
                        "module": id.module.to_string_lossy(),
                        "needs_pin": id.needs_pin,
                        "certificate": cert_json(&id.certificate),
                    })
                })
                .collect();
            let modules: Vec<String> = modules.iter().map(|m| m.to_string_lossy().into_owned()).collect();
            let problems: Vec<String> = listing.problems.iter().map(ToString::to_string).collect();
            Ok(json!({ "count": ids.len(), "ids": ids, "modules": modules, "problems": problems }))
        }
        #[cfg(target_arch = "wasm32")]
        Ok(json!({ "count": 0, "ids": [], "modules": [], "problems": ["PKCS #11 tokens aren't available in the browser"] }))
    }

    /// `{"image": path}` (PNG or JPEG), `{"text": name}` (typed in the script font) or
    /// `{"strokes": [[[x, y], …], …]}` (y up; the drawing pad is 1 wide).
    fn signature_graphic(&self, g: &Value) -> Result<sign::Graphic> {
        let kinds = "graphic must be an object with exactly one of image (a PNG or JPEG path), text, or strokes";
        let Some(o) = g.as_object().filter(|o| o.len() == 1) else { return Err(bad(kinds)) };
        if let Some(path) = o.get("image") {
            let path = self.resolve(path.as_str().ok_or_else(|| bad("graphic.image must be a path"))?, false)?;
            let file = std::fs::File::open(&path).map_err(|e| bad(format!("graphic.image {}: {e}", path.display())))?;
            return Ok(pdfcraft_engine::SignatureImage::read(file).map_err(|e| bad(e.to_string()))?.graphic());
        }
        if let Some(text) = o.get("text") {
            let text = text.as_str().ok_or_else(|| bad("graphic.text must be a string"))?;
            // Nobody sees a preview here: refuse what the script font and its fallback would leave out.
            if let Some(c) = pdfcraft_engine::script_missing(text) {
                return Err(bad(format!(
                    "the signature script font can't draw \"{}\" (U+{:04X}) in graphic.text; type it in Latin, Cyrillic or Greek letters, or pass graphic.image instead",
                    c.escape_debug(),
                    u32::from(c)
                )));
            }
            return pdfcraft_engine::typed_signature_graphic(text).ok_or_else(|| {
                bad(format!(
                    "graphic.text {text:?} has nothing the script font can draw (at most {} characters)",
                    pdfcraft_engine::MAX_SIGNATURE_CHARS
                ))
            });
        }
        if let Some(strokes) = o.get("strokes") {
            let strokes: Vec<Vec<[f64; 2]>> =
                serde_json::from_value(strokes.clone()).map_err(|e| bad(format!("graphic.strokes must be strokes of [x, y] points: {e}")))?;
            return Ok(sign::Graphic::Strokes(strokes));
        }
        Err(bad(kinds))
    }

    pub(crate) fn sign_trust(&mut self, a: &Args) -> Result<Value> {
        let mut certs: Vec<Certificate> =
            if a.opt_bool("clear")?.unwrap_or(false) { Vec::new() } else { self.session.trusted_certificates().to_vec() };
        let paths: Vec<String> = match a.get("paths") {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .ok_or_else(|| bad("paths must be an array"))?
                .iter()
                .map(|p| p.as_str().map(str::to_string).ok_or_else(|| bad("paths must be strings")))
                .collect::<Result<_>>()?,
        };
        for p in paths {
            let path = self.resolve(&p, false)?;
            let bytes = std::fs::read(&path).map_err(|e| failed(format!("{}: {e}", path.display())))?;
            let lower = p.to_ascii_lowercase();
            let found = if lower.ends_with(".p12") || lower.ends_with(".pfx") {
                let id = sign::pkcs12::open(&bytes, a.opt_str("password")?.unwrap_or("")).map_err(failed)?;
                std::iter::once(id.certificate).chain(id.chain).collect()
            } else {
                sign::x509::load_certificates(&bytes).map_err(failed)?
            };
            for c in found {
                if !certs.iter().any(|t| t.raw == c.raw) {
                    certs.push(c);
                }
            }
        }
        self.session.set_trusted_certificates(certs);
        Ok(json!({ "trusted": self.session.trusted_certificates().iter().map(cert_json).collect::<Vec<_>>() }))
    }
}
