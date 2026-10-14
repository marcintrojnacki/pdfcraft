//! Digital IDs on PKCS #11 tokens (Acrobat: Preferences ▸ Signatures ▸ Identities & Trusted
//! Certificates ▸ PKCS#11 Modules and Tokens): smart cards, USB tokens and remote signing services
//! that ship a PKCS #11 module, such as KIR's CloudSigner for mSzafir qualified signatures. The
//! private key stays on the token, which signs the digest PdfCraft gives it: `CKM_RSA_PKCS` over a
//! DigestInfo (what CloudSigner signs), or `CKM_ECDSA`.
//!
//! A module is a shared library loaded into PdfCraft's process, so only modules the user chose
//! are loaded (the app's settings, `PDFCRAFT_PKCS11_MODULES` for the automation tools), plus
//! CloudSigner from where its installer puts it ([`known_modules`]).
//!
//! Remote signing services have each signing approved on the signer's phone. CloudSigner gathers
//! the `C_Sign` calls that arrive within a few seconds into one transaction: one window, one OTT
//! code and one approval for up to [`MAX_PER_TRANSACTION`] signatures. A [`Transaction`] holds
//! each document's `C_Sign` back until every document of the batch is ready (or has failed), then
//! lets them all go at once, each in its own session. Signing a single document is a transaction
//! of one.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use crate::keys::{DigestAlg, ExternalKey, PrivateKey, PublicKey};
use crate::{Certificate, DigitalId, SignError, rsa_pad};

/// Where KIR's CloudSigner installer puts its PKCS #11 module on macOS (mSzafir).
pub const CLOUDSIGNER_MACOS: &str = "/Applications/CloudSigner.app/Contents/Frameworks/libCloudSignerP11.dylib";

/// The most signatures one CloudSigner transaction carries: the mSzafir portal signs 1 to 20
/// documents at once; the service's own limit isn't published.
pub const MAX_PER_TRANSACTION: usize = 20;

/// The PKCS #11 modules installed where their vendors put them: CloudSigner (mSzafir).
pub fn known_modules() -> Vec<PathBuf> {
    [CLOUDSIGNER_MACOS].iter().map(PathBuf::from).filter(|p| p.is_file()).collect()
}

/// Whether `module` is KIR's CloudSigner, whose signatures are approved in the mSzafir app.
pub fn is_cloudsigner(module: &Path) -> bool {
    module.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.to_ascii_lowercase().contains("cloudsigner"))
}

/// The `pkcs11:<SHA-256 of the certificate DER>` reference kept for a token identity. The slot
/// isn't part of it: slot numbers change between runs (a token plugged into another reader,
/// CloudSigner restarted), the certificate doesn't.
pub fn reference(certificate: &Certificate) -> String {
    let digest = DigestAlg::Sha256.digest(&[&certificate.raw]);
    format!("pkcs11:{}", digest.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// A certificate on a token whose private key can sign.
#[derive(Clone, Debug)]
pub struct TokenIdentity {
    pub certificate: Certificate,
    /// The token's other certificates (its CAs), embedded in a signature as a file's chain is.
    pub chain: Vec<Certificate>,
    /// The token's label ("mSzafir Token").
    pub token: String,
    /// The module (shared library) the token is reached through.
    pub module: PathBuf,
    /// The token wants the user's PIN before it signs. Tokens that take the PIN themselves (a
    /// pinpad, or a service such as CloudSigner that shows its own window) don't.
    pub needs_pin: bool,
    slot: Slot,
    /// `CKA_ID`, shared by the certificate and its private key.
    id: Vec<u8>,
}

impl TokenIdentity {
    /// "Name (token label)".
    pub fn display_name(&self) -> String {
        let name = self.certificate.display_name();
        if self.token.is_empty() { name } else { format!("{name} ({})", self.token) }
    }

    /// Open the identity to sign one document. `pin` is used when the token needs one.
    pub fn open(&self, pin: Option<&str>) -> Result<DigitalId, SignError> {
        Transaction::begin(self, pin, 1)?.digital_id()
    }
}

/// A module's tokens' identities, and what couldn't be listed (a module that doesn't load, no
/// token, a certificate PdfCraft can't sign with).
#[derive(Debug, Default)]
pub struct Listing {
    pub ids: Vec<TokenIdentity>,
    pub problems: Vec<Problem>,
}

/// Something a module's listing ran into, as a sentence that says what to do when it can.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub module: PathBuf,
    pub message: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.module.display(), self.message)
    }
}

/// The identities on the tokens of `modules`. A module that can't be read is a problem, not an
/// error: the others are still listed.
pub fn list(modules: &[PathBuf]) -> Listing {
    let mut out = Listing::default();
    for path in modules {
        match list_module(path) {
            Ok(mut l) => {
                for id in l.ids {
                    // The same token can be reached through two modules (a vendor's and OpenSC).
                    if !out.ids.iter().any(|o| o.certificate.raw == id.certificate.raw) {
                        out.ids.push(id);
                    }
                }
                out.problems.append(&mut l.problems);
            }
            Err(e) => out.problems.push(Problem { module: path.clone(), message: e.to_string() }),
        }
    }
    out
}

/// The identity `reference_or_name` names (a [`reference`], or the certificate's common name).
pub fn find(modules: &[PathBuf], reference_or_name: &str) -> Result<TokenIdentity, SignError> {
    let listing = list(modules);
    let name = reference_or_name.strip_prefix("pkcs11:").unwrap_or(reference_or_name);
    if let Some(id) =
        listing.ids.into_iter().find(|id| reference(&id.certificate) == reference_or_name || id.certificate.subject.common_name() == Some(name))
    {
        return Ok(id);
    }
    let mut message = format!("no PKCS #11 token identity {reference_or_name}");
    if modules.is_empty() {
        message.push_str(" (no PKCS #11 module is set up)");
    }
    for p in listing.problems {
        message.push_str("; ");
        message.push_str(&p.to_string());
    }
    Err(SignError::Crypto(message))
}

/// A loaded and initialised module, loaded once per process: a second `C_Initialize` is an error,
/// and finalising one that another caller still uses would break it.
fn module(path: &Path) -> Result<Pkcs11, SignError> {
    static LOADED: OnceLock<Mutex<Vec<(PathBuf, Pkcs11)>>> = OnceLock::new();
    let mut loaded = LOADED.get_or_init(Default::default).lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, m)) = loaded.iter().find(|(p, _)| p == path) {
        return Ok(m.clone());
    }
    let m = Pkcs11::new(path).map_err(|e| SignError::Crypto(format!("the PKCS #11 module {} couldn't be loaded: {e}", path.display())))?;
    match m.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        // Another part of the process initialised it already: it's usable all the same.
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => return Err(SignError::Crypto(format!("the PKCS #11 module {} couldn't start: {e}", path.display()))),
    }
    loaded.push((path.to_path_buf(), m.clone()));
    Ok(m)
}

fn list_module(path: &Path) -> Result<Listing, SignError> {
    let ctx = module(path)?;
    let slots = ctx.get_slots_with_token().map_err(|e| failed(e, path))?;
    let mut out = Listing::default();
    let problem = |message: String| Problem { module: path.to_path_buf(), message };
    if slots.is_empty() {
        let hint = if is_cloudsigner(path) { " (is CloudSigner running, and are you logged in to it?)" } else { "" };
        out.problems.push(problem(format!("no token is present{hint}")));
    }
    for slot in slots {
        if let Err(e) = list_slot(&ctx, path, slot, &mut out) {
            out.problems.push(problem(e.to_string()));
        }
    }
    Ok(out)
}

fn list_slot(ctx: &Pkcs11, path: &Path, slot: Slot, out: &mut Listing) -> Result<(), SignError> {
    let info = ctx.get_token_info(slot).map_err(|e| failed(e, path))?;
    // A blank card in a reader, or SoftHSM's spare slot: nothing on it yet.
    if !info.token_initialized() {
        return Ok(());
    }
    let token = info.label().trim().to_string();
    let needs_pin = info.login_required() && !info.protected_authentication_path();
    let session = ctx.open_ro_session(slot).map_err(|e| failed(e, path))?;
    let mut certs: Vec<(Vec<u8>, Certificate)> = Vec::new();
    for handle in session.find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)]).map_err(|e| failed(e, path))? {
        let attrs = session.get_attributes(handle, &[AttributeType::Value, AttributeType::Id]).map_err(|e| failed(e, path))?;
        let (mut der, mut id) = (None, Vec::new());
        for a in attrs {
            match a {
                Attribute::Value(v) => der = Some(v),
                Attribute::Id(v) => id = v,
                _ => {}
            }
        }
        let Some(der) = der else { continue };
        match Certificate::parse(&der) {
            Ok(c) => certs.push((id, c)),
            Err(e) => out.problems.push(Problem { module: path.to_path_buf(), message: format!("{token}: a certificate can't be read: {e}") }),
        }
    }
    // Private keys are often hidden until the user logs in; then a certificate that may sign
    // documents and isn't a CA's is taken to have its key on the token.
    let key_ids: Vec<Vec<u8>> = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
        .map_err(|e| failed(e, path))?
        .into_iter()
        .filter_map(|k| session.get_attributes(k, &[AttributeType::Id]).ok())
        .filter_map(|attrs| attrs.into_iter().find_map(|a| if let Attribute::Id(v) = a { Some(v) } else { None }))
        .collect();
    let has_key = |id: &[u8], c: &Certificate| {
        if key_ids.is_empty() { !c.is_ca && c.key_usage.is_none_or(|u| u & 0b11 != 0) } else { !id.is_empty() && key_ids.iter().any(|k| k == id) }
    };
    let (mine, others): (Vec<_>, Vec<_>) = certs.into_iter().partition(|(id, c)| has_key(id, c));
    let chain: Vec<Certificate> = others.into_iter().map(|(_, c)| c).collect();
    for (id, certificate) in mine {
        if certificate.public_key.store_signing_key().is_none() {
            let what = certificate.public_key.describe();
            let message = format!("{}: its {what} key can't sign through PdfCraft yet (RSA, P-256 and P-384 only)", certificate.display_name());
            out.problems.push(Problem { module: path.to_path_buf(), message });
            continue;
        }
        out.ids.push(TokenIdentity { certificate, chain: chain.clone(), token: token.clone(), module: path.to_path_buf(), needs_pin, slot, id });
    }
    Ok(())
}

/// What `C_Sign` gets for a key and digest: the mechanism, and whether it is given the digest
/// (raw mechanisms) or the message (the token hashes).
fn mechanism(public: &PublicKey, alg: DigestAlg, supported: &[MechanismType], multipart: bool) -> Result<(Mechanism<'static>, bool), SignError> {
    let has = |m: MechanismType| supported.is_empty() || supported.contains(&m);
    let rsa = matches!(public, PublicKey::Rsa { .. });
    // Raw mechanisms (the token signs what it is given) can't be fed in parts.
    if !multipart {
        if rsa && has(MechanismType::RSA_PKCS) {
            return Ok((Mechanism::RsaPkcs, true));
        }
        if !rsa && has(MechanismType::ECDSA) {
            return Ok((Mechanism::Ecdsa, true));
        }
    }
    let m = match (rsa, alg) {
        (true, DigestAlg::Sha384) => Mechanism::Sha384RsaPkcs,
        (true, DigestAlg::Sha512) => Mechanism::Sha512RsaPkcs,
        (true, _) => Mechanism::Sha256RsaPkcs,
        (false, DigestAlg::Sha384) => Mechanism::EcdsaSha384,
        (false, DigestAlg::Sha512) => Mechanism::EcdsaSha512,
        (false, _) => Mechanism::EcdsaSha256,
    };
    if has(m.mechanism_type()) {
        Ok((m, false))
    } else {
        Err(SignError::Unsupported(format!("the token offers no mechanism to sign with its {} key", public.describe())))
    }
}

/// One batch of signatures made together: CloudSigner's transaction (one approval for all), and
/// for other tokens one login for all. Each document's signing waits in `C_Sign` for the others,
/// so every document of the batch must be signed or dropped; [`Transaction::digital_id`] hands
/// out one digital ID per document.
pub struct Transaction {
    identity: TokenIdentity,
    ctx: Pkcs11,
    pin: Option<AuthPin>,
    /// Keeps the token logged in while the batch signs (a token logs out when its last session
    /// closes).
    _login: Option<Mutex<Session>>,
    gate: Gate,
}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transaction({}, {} signatures)", self.identity.display_name(), self.gate.expected)
    }
}

impl Transaction {
    /// Start a batch of `signatures` signatures with `identity`, logging in with `pin` when the
    /// token needs it.
    pub fn begin(identity: &TokenIdentity, pin: Option<&str>, signatures: usize) -> Result<Arc<Transaction>, SignError> {
        let ctx = module(&identity.module)?;
        let pin = pin.filter(|p| !p.is_empty()).map(|p| AuthPin::from(p.to_string()));
        let login = if identity.needs_pin {
            let pin = pin.as_ref().ok_or_else(|| SignError::Crypto(format!("{} needs its PIN", identity.token)))?;
            let session = ctx.open_ro_session(identity.slot).map_err(|e| failed(e, &identity.module))?;
            match session.login(UserType::User, Some(pin)) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
                Err(e) => return Err(failed(e, &identity.module)),
            }
            Some(Mutex::new(session))
        } else {
            None
        };
        Ok(Arc::new(Transaction { identity: identity.clone(), ctx, pin, _login: login, gate: Gate::new(signatures) }))
    }

    /// A digital ID for one document of the batch. Its signing waits until every document has
    /// reached its signing or given up (its digital ID dropped unsigned).
    pub fn digital_id(self: &Arc<Self>) -> Result<DigitalId, SignError> {
        if !self.gate.join() {
            return Err(SignError::Crypto(format!("the batch has {} signatures already", self.gate.expected)));
        }
        let public = self.identity.certificate.public_key.clone();
        let key = TokenKey { tx: Arc::clone(self), public: public.clone(), settled: Mutex::new(false) };
        Ok(DigitalId {
            key: PrivateKey::external(public, Arc::new(key)),
            certificate: self.identity.certificate.clone(),
            chain: self.identity.chain.clone(),
            friendly_name: Some(self.identity.display_name()),
        })
    }

    fn private_key(&self, session: &Session) -> Result<ObjectHandle, SignError> {
        let class = Attribute::Class(ObjectClass::PRIVATE_KEY);
        if !self.identity.id.is_empty() {
            let found =
                session.find_objects(&[class.clone(), Attribute::Id(self.identity.id.clone())]).map_err(|e| failed(e, &self.identity.module))?;
            if let Some(k) = found.first() {
                return Ok(*k);
            }
        }
        // A key without an ID: only a token's only key can be told to be the certificate's.
        match session.find_objects(&[class]).map_err(|e| failed(e, &self.identity.module))?.as_slice() {
            [k] => Ok(*k),
            [] => Err(SignError::Crypto(format!(
                "{}: the private key for {} isn't on the token",
                self.identity.token,
                self.identity.certificate.display_name()
            ))),
            _ => Err(SignError::Crypto(format!(
                "{}: the private key for {} can't be told apart from the token's other keys",
                self.identity.token,
                self.identity.certificate.display_name()
            ))),
        }
    }
}

/// The batch's meeting point: no `C_Sign` starts before every document has arrived at its
/// signing or given up.
struct Gate {
    expected: usize,
    state: Mutex<GateState>,
    all_in: Condvar,
}

#[derive(Default)]
struct GateState {
    /// Digital IDs handed out.
    joined: usize,
    /// Documents at their signing, or given up.
    settled: usize,
}

impl Gate {
    fn new(expected: usize) -> Gate {
        Gate { expected: expected.max(1), state: Mutex::new(GateState::default()), all_in: Condvar::new() }
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn join(&self) -> bool {
        let mut s = self.lock();
        if s.joined >= self.expected {
            return false;
        }
        s.joined += 1;
        true
    }

    fn settle(&self) {
        let mut s = self.lock();
        s.settled = s.settled.saturating_add(1);
        self.all_in.notify_all();
    }

    fn wait_for_everyone(&self) {
        let mut s = self.lock();
        while s.settled < self.expected {
            s = self.all_in.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// One document's key in a [`Transaction`].
struct TokenKey {
    tx: Arc<Transaction>,
    public: PublicKey,
    /// This document has arrived at its signing or given up (it counts once).
    settled: Mutex<bool>,
}

impl TokenKey {
    fn settle(&self) {
        let mut settled = self.settled.lock().unwrap_or_else(PoisonError::into_inner);
        if !*settled {
            *settled = true;
            self.tx.gate.settle();
        }
    }
}

impl Drop for TokenKey {
    /// A document that ends without signing doesn't keep the rest of the batch waiting.
    fn drop(&mut self) {
        self.settle();
    }
}

impl ExternalKey for TokenKey {
    fn sign(&self, alg: DigestAlg, msg: &[u8]) -> Result<Vec<u8>, SignError> {
        let tx = &self.tx;
        let module = &tx.identity.module;
        // Everything that can fail before the token is asked happens first, so a failure here
        // gives up this document alone.
        let prepared = (|| {
            let session = tx.ctx.open_ro_session(tx.identity.slot).map_err(|e| failed(e, module))?;
            let key = tx.private_key(&session)?;
            // A key that wants its PIN again for every signature (CKA_ALWAYS_AUTHENTICATE): the PIN is
            // given between C_SignInit and the data, so the token must hash in parts.
            let always = session
                .get_attributes(key, &[AttributeType::AlwaysAuthenticate])
                .map(|a| a.iter().any(|a| matches!(a, Attribute::AlwaysAuthenticate(true))))
                .unwrap_or(false);
            let supported = tx.ctx.get_mechanism_list(tx.identity.slot).unwrap_or_default();
            let (mechanism, raw) = mechanism(&self.public, alg, &supported, always)?;
            Ok::<_, SignError>((session, key, always, mechanism, raw))
        })();
        self.settle();
        let (session, key, always, mechanism, raw) = prepared?;
        tx.gate.wait_for_everyone();
        let data = if raw {
            let digest = alg.digest(&[msg]);
            if matches!(self.public, PublicKey::Rsa { .. }) { rsa_pad::digest_info(alg, &digest, true) } else { digest }
        } else {
            msg.to_vec()
        };
        let signature = if always {
            session.sign_init(&mechanism, key).map_err(|e| failed(e, module))?;
            match session.login(UserType::ContextSpecific, tx.pin.as_ref()) {
                Ok(()) => {}
                Err(e) => return Err(failed(e, module)),
            }
            session.sign_update(&data).and_then(|()| session.sign_final()).map_err(|e| failed(e, module))?
        } else {
            session.sign(&mechanism, key, &data).map_err(|e| failed(e, module))?
        };
        // A raw ECDSA signature is `r ‖ s`; RSA comes back as it is.
        self.public.store_signature_der(&signature)
    }
}

/// A PKCS #11 error as a [`SignError`] that says what to do about it.
fn failed(e: CkError, module: &Path) -> SignError {
    let CkError::Pkcs11(rv, function) = &e else { return SignError::Crypto(format!("{}: {e}", module.display())) };
    let cloudsigner = is_cloudsigner(module);
    match rv {
        RvError::PinIncorrect => SignError::WrongPassword,
        RvError::PinLocked => SignError::Crypto("the token's PIN is locked".into()),
        RvError::FunctionFailed | RvError::FunctionCanceled if cloudsigner => SignError::Crypto(format!(
            "CloudSigner returned no signature: it was rejected in the mSzafir app, the time to approve it ran out, or it was cancelled in CloudSigner's window ({function}: {rv:?})"
        )),
        RvError::FunctionCanceled => SignError::Crypto("signing was cancelled on the token".into()),
        RvError::TokenNotPresent | RvError::DeviceRemoved | RvError::SessionHandleInvalid | RvError::SlotIdInvalid => {
            let hint = if cloudsigner { " (is CloudSigner running, and are you logged in to it?)" } else { " (is it connected?)" };
            SignError::Crypto(format!("the token isn't available{hint} ({function}: {rv:?})"))
        }
        _ => SignError::Crypto(format!("{}: {function} failed: {rv:?} ({rv})", module.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudsigner_is_recognised_by_its_library_name() {
        assert!(is_cloudsigner(Path::new(CLOUDSIGNER_MACOS)));
        assert!(is_cloudsigner(Path::new(r"C:\Program Files\CloudSigner\CloudSignerP11.dll")));
        assert!(!is_cloudsigner(Path::new("/usr/lib/softhsm/libsofthsm2.so")));
    }

    #[test]
    fn raw_mechanisms_are_preferred_and_hashing_ones_are_the_fallback() {
        let rsa = PublicKey::Rsa { n: vec![0xc5; 256], e: vec![1, 0, 1] };
        let p256 = PublicKey::P256(vec![4; 65]);
        let pick = |k: &PublicKey, alg, supported: &[MechanismType], multipart| {
            mechanism(k, alg, supported, multipart).map(|(m, raw)| (m.mechanism_type(), raw))
        };
        // A token that lists nothing is assumed to sign raw (CloudSigner signs CKM_RSA_PKCS).
        assert_eq!(pick(&rsa, DigestAlg::Sha256, &[], false).ok(), Some((MechanismType::RSA_PKCS, true)));
        assert_eq!(pick(&p256, DigestAlg::Sha256, &[], false).ok(), Some((MechanismType::ECDSA, true)));
        // Signing in parts (a key that wants its PIN for every signature) hashes on the token.
        assert_eq!(pick(&rsa, DigestAlg::Sha384, &[], true).ok(), Some((MechanismType::SHA384_RSA_PKCS, false)));
        assert_eq!(pick(&p256, DigestAlg::Sha256, &[], true).ok(), Some((MechanismType::ECDSA_SHA256, false)));
        // Only hashing mechanisms offered.
        assert_eq!(pick(&rsa, DigestAlg::Sha256, &[MechanismType::SHA256_RSA_PKCS], false).ok(), Some((MechanismType::SHA256_RSA_PKCS, false)));
        // Nothing that fits.
        assert!(pick(&rsa, DigestAlg::Sha256, &[MechanismType::ECDSA], false).is_err());
    }

    #[test]
    fn a_gate_opens_when_everyone_has_arrived_or_given_up() {
        let gate = Arc::new(Gate::new(3));
        assert!(gate.join() && gate.join() && gate.join());
        assert!(!gate.join(), "no fourth document in a batch of three");
        let waiter = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || gate.wait_for_everyone())
        };
        gate.settle();
        gate.settle();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!waiter.is_finished(), "two of three isn't everyone");
        gate.settle();
        assert!(waiter.join().is_ok());
    }
}
