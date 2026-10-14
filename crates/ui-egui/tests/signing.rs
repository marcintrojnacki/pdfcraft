//! Use a certificate in the real shell: draw a signature, create a digital ID, sign, validate.

use egui::{Pos2, pos2};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use pdfcraft_engine::SignatureStatus;
use pdfcraft_ui_egui::{Dialog, PdfCraftApp, QuickTool, RightPanel, SignStep};

const FIXTURE: &[u8] = b"%PDF-1.7
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length 45 >> stream
BT /F1 14 Tf 20 150 Td (Please sign below) Tj ET
endstream endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj
trailer << /Root 1 0 R >>
%%EOF";

/// A fresh folder per call: tests run in parallel and must not remove each other's files.
fn dir() -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("pdfcraft-signing-ui-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn harness(dir: std::path::PathBuf) -> Harness<'static, PdfCraftApp> {
    let mut h = Harness::builder().with_size(egui::vec2(1400.0, 900.0)).build_eframe(move |_cc| {
        let mut app = PdfCraftApp::new();
        app.set_option("language", "en").unwrap();
        app.open_bytes("contract.pdf", None, FIXTURE.to_vec()).expect("opens");
        app.set_option("left", "closed").unwrap();
        app.export_dir_override = Some(dir.to_string_lossy().into_owned());
        app.save_override = Some(dir.join("contract_signed.pdf").to_string_lossy().into_owned());
        app
    });
    h.run_steps(6);
    h
}

fn at(h: &Harness<'static, PdfCraftApp>, x: f32, y: f32) -> Pos2 {
    let r = h.state().views[0].page_screen_rect(0).expect("page 1 on screen");
    pos2(r.left() + x / 300.0 * r.width(), r.top() + (200.0 - y) / 200.0 * r.height())
}

fn drag(h: &mut Harness<'static, PdfCraftApp>, from: Pos2, to: Pos2) {
    h.hover_at(from);
    h.run_steps(1);
    h.drag_at(from);
    h.run_steps(1);
    for k in 1..=4 {
        h.hover_at(from + (to - from) * (k as f32 / 4.0));
        h.run_steps(1);
    }
    h.drop_at(to);
    h.run_steps(3);
}

fn field<'a>(h: &'a Harness<'static, PdfCraftApp>, label: &'a str) -> egui_kittest::Node<'a> {
    h.get_all_by_label(label).last().unwrap_or_else(|| panic!("no {label:?}"))
}

#[test]
fn drawing_a_signature_creating_an_id_signing_and_trusting() {
    let dir = dir();
    let mut h = harness(dir.clone());
    assert!(h.state_mut().execute("sign.digital"));
    assert_eq!(h.state().quick_tool, QuickTool::SignArea { certify: false });
    let (a, b) = (at(&h, 40.0, 90.0), at(&h, 220.0, 40.0));
    drag(&mut h, a, b);
    assert_eq!(h.state().dialog, Some(Dialog::Sign));
    assert_eq!(h.state().sign_draft.as_ref().map(|d| d.step), Some(SignStep::Configure), "no IDs yet: configure one");

    // Create a new digital ID (P-256 keeps the test fast).
    h.get_by_label("Configure a Digital ID for Signing");
    field(&h, "Name").click();
    h.run_steps(1);
    field(&h, "Name").type_text("Grace Hopper");
    h.state_mut().sign_draft.as_mut().unwrap().new_id.key = 3;
    for (label, text) in [("Password", "secret1"), ("Confirm Password", "secret1")] {
        field(&h, label).click();
        h.run_steps(1);
        field(&h, label).type_text(text);
        h.run_steps(1);
    }
    h.get_by_label("Save").click();
    h.run_steps(3);
    assert_eq!(h.state().digital_ids.len(), 1);
    assert!(std::path::Path::new(&h.state().digital_ids[0].path).exists(), "saved as a .p12");
    h.get_by_label("Grace Hopper");
    h.get_by_label("Continue").click();
    h.run_steps(2);
    h.get_by_label("Sign as \"Grace Hopper\"");

    // A wrong password says so.
    field(&h, "Digital ID password").click();
    h.run_steps(1);
    field(&h, "Digital ID password").type_text("nope");
    h.get_by_label("Sign").click();
    h.run_steps(3);
    h.get_by_label("The password is incorrect.");
    h.state_mut().sign_draft.as_mut().unwrap().password = "secret1".into();
    field(&h, "Reason").click();
    h.run_steps(1);
    field(&h, "Reason").type_text("I approve");
    h.get_by_label("Sign").click();
    h.run_steps(6);

    let s = h.state();
    assert_eq!(s.dialog, None);
    assert!(dir.join("contract_signed.pdf").exists());
    let doc = s.session.get(s.views[0].id).unwrap();
    assert_eq!(doc.name, "contract_signed.pdf");
    let sig = doc.signatures.iter().find(|x| x.signed).expect("signed");
    assert_eq!((sig.status, sig.reason.as_deref(), sig.page), (SignatureStatus::Unknown, Some("I approve"), Some(0)));
    assert_eq!(s.right, Some(RightPanel::Signatures));
    h.get_by_label("At least one signature has problems.");

    // Signatures panel: expand, trust the signer → valid.
    h.get_by_label_contains("Signed by Grace Hopper").click();
    h.run_steps(2);
    h.get_by_label("Signature validity is UNKNOWN:");
    h.get_by_label("Add to trusted certificates").click();
    h.run_steps(3);
    h.get_by_label("Signed and all signatures are valid.");
    let s = h.state();
    assert_eq!(s.session.get(s.views[0].id).unwrap().signatures[0].status, SignatureStatus::Valid);
    // Show certificate: the Certificate Viewer.
    h.get_by_label("Show certificate…").click();
    h.run_steps(3);
    h.get_by_label("Certificate Viewer");
    assert!(h.get_all_by_label_contains("CN=Grace Hopper").count() >= 2, "issued to and by (self-signed)");
    h.run_steps(2);
    h.get_by_label("Details").click();
    h.run_steps(2);
    h.get_by_label("SHA-256 digest");
    h.run_steps(2);
    h.get_by_label("Trust").click();
    h.run_steps(2);

    h.get_by_label("This certificate is in your list of trusted certificates.");
    h.run_steps(2);
    h.get_by_label("OK").click();
    h.run_steps(2);
    assert_eq!(h.state().dialog, None);
    // View signed version opens the bytes the signature covers as a new document.
    h.get_by_label("View signed version").click();
    h.run_steps(3);
    let s = h.state();
    assert_eq!(s.views.len(), 2);
    let v = s.session.get(s.views[1].id).unwrap();
    assert!(v.name.contains("signed version") && v.signatures.iter().any(|x| x.signed));
    // Trusted certificates and the ID list persist.
    let saved = s.persist();
    let mut fresh = PdfCraftApp::new();
    fresh.set_option("language", "en").unwrap();
    fresh.restore(&saved);
    assert_eq!((fresh.digital_ids.len(), fresh.session.trusted_certificates().len()), (1, 1));
}

#[test]
fn certifying_without_a_visible_signature() {
    let dir = dir().join("certify");
    std::fs::create_dir_all(&dir).unwrap();
    let mut h = harness(dir.clone());
    // An ID from a file.
    let p12 = concat!(env!("CARGO_MANIFEST_DIR"), "/../sign/tests/data/ec-p256.p12");
    assert!(h.state_mut().execute("sign.certify_invisible"));
    h.run_steps(2);
    {
        let d = h.state_mut().sign_draft.as_mut().unwrap();
        assert_eq!((d.rect, d.certify), (None, Some(2)));
        d.new_id.create = false;
        d.new_id.file = p12.into();
        d.new_id.file_password = "test".into();
    }
    h.run_steps(1);
    h.get_by_label("Continue").click();
    h.run_steps(2);
    assert_eq!(h.state().digital_ids.len(), 1);
    // The dialog shrinks onto this step. egui centers an area from the previous frame's size,
    // so give the buttons a frame to land before clicking.
    h.run_steps(2);
    h.get_by_label("Continue").click();
    h.run_steps(2);
    h.get_by_label("Certify as \"Test Signer EC\"");
    h.get_by_label("Permitted actions after certifying");
    h.state_mut().sign_draft.as_mut().unwrap().password = "test".into();
    h.get_by_label("Sign").click();
    h.run_steps(6);
    let s = h.state();
    assert_eq!(s.sign_draft.as_ref().and_then(|d| d.error.clone()), None);
    let doc = s.session.get(s.views[0].id).unwrap();
    let sig = doc.signatures.iter().find(|x| x.signed).unwrap();
    assert_eq!((sig.certify, sig.visible), (Some(2), false));
    h.get_by_label_contains("Certified by Test Signer EC");
}

/// The fixture with an empty signature field across the bottom of the page.
const WITH_FIELD: &[u8] = b"%PDF-1.7
1 0 obj << /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Annots [6 0 R] >> endobj
6 0 obj << /Type /Annot /Subtype /Widget /FT /Sig /T (Approver) /Rect [20 20 280 80] /P 3 0 R /F 4 >> endobj
trailer << /Root 1 0 R >>
%%EOF";

#[test]
fn clicking_an_empty_signature_field_signs_it() {
    let dir = dir().join("field");
    std::fs::create_dir_all(&dir).unwrap();
    let mut h = harness(dir.clone());
    h.state_mut().open_bytes("form.pdf", None, WITH_FIELD.to_vec()).unwrap();
    h.state_mut().active = Some(1);
    h.run_steps(6);
    let p = {
        let r = h.state().views[1].page_screen_rect(0).expect("on screen");
        pos2(r.left() + 150.0 / 300.0 * r.width(), r.top() + (200.0 - 50.0) / 200.0 * r.height())
    };
    h.hover_at(p);
    h.run_steps(1);
    h.drag_at(p);
    h.run_steps(1);
    h.drop_at(p);
    h.run_steps(3);
    assert_eq!(h.state().dialog, Some(Dialog::Sign));
    assert_eq!(h.state().sign_draft.as_ref().and_then(|d| d.field.clone()).as_deref(), Some("Approver"));
    let entry = {
        let id = pdfcraft_engine::sign::pkcs12::open(
            &std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../sign/tests/data/ec-p256.p12")).unwrap(),
            "test",
        )
        .unwrap();
        h.state_mut().add_digital_id(concat!(env!("CARGO_MANIFEST_DIR"), "/../sign/tests/data/ec-p256.p12"), &id.certificate)
    };
    {
        let d = h.state_mut().sign_draft.as_mut().unwrap();
        d.selected = Some(entry);
        d.step = SignStep::SignAs;
        d.password = "test".into();
    }
    h.run_steps(2);
    h.get_by_label("Sign").click();
    h.run_steps(6);
    let s = h.state();
    let sig = s.session.get(s.views[1].id).unwrap().signatures.iter().find(|x| x.field == "Approver").cloned().unwrap();
    assert!(sig.signed && sig.visible);
}

#[test]
fn the_fill_and_sign_signature_or_an_image_shows_in_a_digital_signature() {
    use pdfcraft_ui_egui::SignGraphic;
    use pdfcraft_ui_egui::fill_sign::SavedSig;
    let dir = dir().join("graphic");
    std::fs::create_dir_all(&dir).unwrap();
    let mut h = harness(dir.clone());
    let p12 = concat!(env!("CARGO_MANIFEST_DIR"), "/../sign/tests/data/ec-p256.p12");
    let cert = pdfcraft_engine::sign::pkcs12::open(&std::fs::read(p12).unwrap(), "test").unwrap().certificate;
    let sign_as = |h: &mut Harness<'static, PdfCraftApp>, rect: [f64; 4]| {
        h.state_mut().start_signing(0, Some(rect), None, None);
        let entry = h.state_mut().add_digital_id(p12, &cert);
        let d = h.state_mut().sign_draft.as_mut().unwrap();
        (d.selected, d.step, d.password) = (Some(entry), SignStep::SignAs, "test".into());
        h.run_steps(2);
    };

    // Without a saved Fill & Sign signature there is nothing to choose.
    sign_as(&mut h, [20.0, 110.0, 280.0, 140.0]);
    h.get_by_label("Graphic");
    assert!(h.get_by_label("Fill & Sign signature").accesskit_node().is_disabled(), "disabled without one");
    h.get_by_label("Cancel").click();
    h.run_steps(2);

    // The saved signature (typed here) takes the name's place.
    h.state_mut().signature = Some(SavedSig::Typed("Grace Hopper".into()));
    sign_as(&mut h, [20.0, 110.0, 280.0, 140.0]);
    h.get_by_label("Fill & Sign signature").click();
    h.run_steps(2);
    assert_eq!(h.state().sign_draft.as_ref().unwrap().graphic, SignGraphic::FillSign);
    h.get_by_label("Sign").click();
    h.run_steps(6);
    let s = h.state();
    assert_eq!(s.sign_draft.as_ref().and_then(|d| d.error.clone()), None);
    let sig = s.session.get(s.views[0].id).unwrap().signatures.iter().find(|x| x.signed).cloned().unwrap();
    assert!(sig.visible && sig.status == SignatureStatus::Unknown, "{:?}", sig.details);
    // Remembered for the next signature, and across a restart.
    assert_eq!(s.sign_graphic, SignGraphic::FillSign);
    sign_as(&mut h, [20.0, 20.0, 280.0, 60.0]);
    assert_eq!(h.state().sign_draft.as_ref().unwrap().graphic, SignGraphic::FillSign);

    // An image (the picker's result is set directly: the file dialog is native).
    let image = {
        let mut png = std::io::Cursor::new(Vec::new());
        image::RgbaImage::from_pixel(60, 20, image::Rgba([200, 0, 0, 255])).write_to(&mut png, image::ImageFormat::Png).unwrap();
        pdfcraft_engine::SignatureImage::from_bytes(png.get_ref()).unwrap()
    };
    h.state_mut().sign_draft.as_mut().unwrap().graphic = SignGraphic::Image(image.clone());
    h.run_steps(2);
    h.get_by_label("Choose image…");
    h.get_by_label("Sign").click();
    h.run_steps(6);
    let s = h.state();
    assert_eq!(s.sign_draft.as_ref().and_then(|d| d.error.clone()), None);
    let signed = std::fs::read(dir.join("contract_signed.pdf")).unwrap();
    assert!(signed.windows(6).any(|w| w == b"/Image"), "the image is embedded");
    assert_eq!(s.session.get(s.views[0].id).unwrap().signatures.iter().filter(|x| x.signed).count(), 2);
    let mut fresh = PdfCraftApp::new();
    fresh.restore(&s.persist());
    assert_eq!(fresh.sign_graphic, SignGraphic::Image(image));
    // A saved choice that can't be read back falls back to the name.
    fresh.restore(r#"{"sign_graphic": {"Image": "not base64"}}"#);
    assert_eq!(fresh.sign_graphic, SignGraphic::Name);
}

#[test]
fn os_store_identities_are_not_persisted() {
    let mut app = PdfCraftApp::new();
    app.set_option("language", "en").unwrap();
    for path in ["windows:Store signer", "keychain:Store signer", "file-id.p12"] {
        app.digital_ids.push(pdfcraft_ui_egui::DigitalIdEntry {
            path: path.into(),
            name: "Signer".into(),
            issuer: "Test issuer".into(),
            email: String::new(),
            expires: "2030.01.01".into(),
            unusable: None,
        });
    }
    let saved = app.persist();
    let settings: serde_json::Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(settings["digital_ids"].as_array().unwrap().len(), 1);
    assert_eq!(settings["digital_ids"][0]["path"], "file-id.p12");
    let mut restored = PdfCraftApp::new();
    restored.set_option("language", "en").unwrap();
    restored.restore(&saved);
    assert_eq!(restored.digital_ids.len(), 1);
    assert_eq!(restored.digital_ids[0].path, "file-id.p12");
}

#[test]
fn windows_store_identity_does_not_ask_for_a_file_password() {
    let mut h = harness(dir());
    h.state_mut().start_signing(0, None, None, None);
    // A synthetic picker entry exercises the dialog without a real Windows identity.
    h.state_mut().digital_ids.push(pdfcraft_ui_egui::DigitalIdEntry {
        path: "windows:No Such Signer".into(),
        name: "Store signer".into(),
        issuer: "Test issuer".into(),
        email: String::new(),
        expires: "2030.01.01".into(),
        unusable: None,
    });
    let draft = h.state_mut().sign_draft.as_mut().unwrap();
    draft.step = SignStep::Choose;
    draft.selected = Some(0);
    h.run_steps(3);
    h.get_by_label("Continue").click();
    h.run_steps(3);
    h.get_by_label("Sign as \"Store signer\"");
    assert_eq!(h.query_all_by_label("Digital ID password").count(), 0);
    h.get_by_label("The key is in the Windows certificate store, which may ask to allow PdfCraft to use it.");
    h.get_by_label("Sign").click();
    h.run_steps(3);
    assert_eq!(h.state().dialog, Some(Dialog::Sign));
    assert!(h.state().sign_draft.as_ref().unwrap().error.as_ref().unwrap().contains("Windows certificate store"));
}

/// Certificate names are as long as their owners made them: the picker cuts both lines of a
/// row with "…" instead of painting them past the dialog's edge.
#[test]
fn long_digital_id_names_stay_inside_the_picker() {
    let mut h = harness(dir());
    h.state_mut().start_signing(0, None, None, None);
    let long = "a certificate subject much longer than the picker is wide ".repeat(4);
    h.state_mut().digital_ids.push(pdfcraft_ui_egui::DigitalIdEntry {
        path: "windows:No Such Signer".into(),
        name: long.clone(),
        issuer: long,
        email: String::new(),
        expires: "2030.01.01".into(),
        unusable: None,
    });
    h.state_mut().sign_draft.as_mut().unwrap().step = SignStep::Choose;
    h.run_steps(3);
    let right = h.get_by_label("Continue").rect().right();
    let lines: Vec<_> = h
        .output()
        .shapes
        .iter()
        .filter_map(|s| match &s.shape {
            egui::Shape::Text(t) if t.galley.job.text.contains("much longer") => Some(t),
            _ => None,
        })
        .collect();
    assert_eq!(lines.len(), 2, "the name and the details line");
    for line in lines {
        assert!(line.galley.elided, "{}", line.galley.job.text);
        assert!(
            line.pos.x + line.galley.size().x <= right,
            "the line ends at {} but the dialog's buttons end at {right}",
            line.pos.x + line.galley.size().x
        );
    }
}

/// A store certificate that can't sign is shown with its reason (so the user learns why an
/// identity Acrobat lists is missing, issue #179) but is never selected or chosen.
#[test]
fn an_unusable_id_is_shown_with_its_reason_and_cannot_be_chosen() {
    let mut h = harness(dir());
    // Not a `windows:` path: those are replaced by the real store listing when signing starts.
    h.state_mut().digital_ids.push(pdfcraft_ui_egui::DigitalIdEntry {
        path: "store-test:broken".into(),
        name: "Broken signer".into(),
        issuer: String::new(),
        email: String::new(),
        expires: String::new(),
        unusable: Some("its private key can't be opened: the key is missing from its key store (Windows error 0x80090016)".into()),
    });
    h.state_mut().start_signing(0, None, None, None);
    h.run_steps(3);
    let draft = h.state().sign_draft.as_ref().unwrap();
    assert_eq!(draft.step, SignStep::Choose, "shown, with its reason, rather than skipped to Configure");
    assert_eq!(draft.selected, None);
    h.get_by_label("Broken signer").click();
    h.run_steps(3);
    assert_eq!(h.state().sign_draft.as_ref().unwrap().selected, None);
    h.get_by_label("Continue").click();
    h.run_steps(3);
    assert_eq!(h.state().sign_draft.as_ref().unwrap().step, SignStep::Choose);
    // A usable ID after it is the one selected to begin with.
    h.state_mut().digital_ids.push(pdfcraft_ui_egui::DigitalIdEntry {
        path: "store-test:fine".into(),
        name: "Working signer".into(),
        issuer: "Test issuer".into(),
        email: String::new(),
        expires: "2030.01.01".into(),
        unusable: None,
    });
    h.state_mut().start_signing(0, None, None, None);
    h.run_steps(3);
    assert_eq!(h.state().sign_draft.as_ref().unwrap().selected, Some(1));
}

/// Issue #1396: an imported digital ID can be removed from Sign with a Digital ID, after a
/// confirmation, and its file stays where it was.
#[test]
fn an_imported_digital_id_can_be_removed() {
    let dir = dir().join("remove");
    std::fs::create_dir_all(&dir).unwrap();
    let p12 = dir.join("signer.p12");
    std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/../sign/tests/data/ec-p256.p12"), &p12).unwrap();
    let mut h = harness(dir.clone());
    assert!(h.state_mut().execute("sign.certify_invisible"));
    h.run_steps(2);
    {
        let d = h.state_mut().sign_draft.as_mut().unwrap();
        d.new_id.create = false;
        d.new_id.file = p12.to_string_lossy().into_owned();
        d.new_id.file_password = "test".into();
    }
    h.run_steps(1);
    h.get_by_label("Continue").click();
    h.run_steps(4);
    assert_eq!(h.state().digital_ids.len(), 1);
    assert_eq!(h.state().sign_draft.as_ref().map(|d| d.step), Some(SignStep::Choose));

    // Remove asks first, and Cancel keeps the ID. The dialog changes size with the question;
    // egui centres it from the previous frame's size, so let it settle before each click.
    h.get_by_label("Remove").click();
    h.run_steps(4);
    h.get_by_label("Remove \"Test Signer EC\" from this list? The file itself is not deleted.");
    // The question's Cancel comes before the dialog's own.
    h.get_all_by_label("Cancel").next().unwrap().click();
    h.run_steps(4);
    assert!(h.query_by_label_contains("from this list?").is_none());
    assert_eq!(h.state().digital_ids.len(), 1);

    h.get_by_label("Remove").click();
    h.run_steps(4);
    h.get_by_label("Remove").click();
    h.run_steps(3);
    assert!(h.state().digital_ids.is_empty());
    assert!(p12.exists(), "the file itself is not deleted");
    // With no IDs left the dialog offers to configure one.
    assert_eq!(h.state().sign_draft.as_ref().map(|d| d.step), Some(SignStep::Configure));
    h.get_by_label("Configure a Digital ID for Signing");
}

/// A PKCS #11 module and its token, end to end through the dialog on SoftHSM (a software
/// token): Configure New Digital ID ▸ signature creation device, the PIN, signing on a worker
/// while the app goes on, the module kept in the settings, and CloudSigner's approval hint.
/// Skipped when SoftHSM isn't installed. SoftHSM reads its token folder from `SOFTHSM2_CONF`,
/// so the checks run in a child process (this test binary again).
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn a_pkcs11_device_signs_through_the_dialog() {
    let Some(lib) = pkcs11_device::softhsm() else {
        eprintln!("SoftHSM isn't installed: PKCS #11 signing in the dialog not checked");
        return;
    };
    let dir = dir();
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    let conf = dir.join("softhsm2.conf");
    std::fs::write(&conf, format!("directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n", dir.join("tokens").display()))
        .unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "pkcs11_device::dialog_checks", "--ignored", "--nocapture", "--test-threads=1"])
        .env("SOFTHSM2_CONF", &conf)
        .env("PDFCRAFT_TEST_SOFTHSM_LIB", &lib)
        .env("PDFCRAFT_TEST_WORKDIR", &dir)
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{text}");
    assert!(text.contains("1 passed"), "the checks ran: {text}");
}

#[cfg(not(target_arch = "wasm32"))]
mod pkcs11_device {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle};
    use cryptoki::session::{Session, UserType};
    use cryptoki::types::AuthPin;
    use pdfcraft_engine::sign::keys::{DigestAlg, ExternalKey};
    use pdfcraft_engine::sign::{Certificate, Name, PrivateKey, PublicKey, SignError, Time, der};

    use super::*;

    const PIN: &str = "135790";

    pub(super) fn softhsm() -> Option<PathBuf> {
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

    /// A token "UI test" holding one RSA identity, "Device Signer".
    fn set_up_token(lib: &std::path::Path) {
        let ctx = Pkcs11::new(lib).unwrap();
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).unwrap();
        let free = *ctx.get_slots_with_token().unwrap().first().unwrap();
        let so = AuthPin::from("so-secret".to_string());
        ctx.init_token(free, &so, "UI test").unwrap();
        let slot =
            ctx.get_slots_with_token().unwrap().into_iter().find(|s| ctx.get_token_info(*s).is_ok_and(|i| i.label().trim() == "UI test")).unwrap();
        let session = ctx.open_rw_session(slot).unwrap();
        session.login(UserType::So, Some(&so)).unwrap();
        session.init_pin(&AuthPin::from(PIN.to_string())).unwrap();
        session.logout().unwrap();
        session.login(UserType::User, Some(&AuthPin::from(PIN.to_string()))).unwrap();
        let keeper = ctx.open_rw_session(slot).unwrap();
        let common = [Attribute::Token(true), Attribute::Id(vec![9])];
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
        let cert =
            Certificate::self_signed(&Name::build("Device Signer", "", "PdfCraft tests", "", "PL"), &key, Time::from_unix(1_767_225_600), 5, &[9])
                .unwrap();
        drop(key);
        keeper
            .create_object(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Token(true),
                Attribute::Id(vec![9]),
                Attribute::Subject(cert.subject.raw.clone()),
                Attribute::Value(cert.raw.clone()),
            ])
            .unwrap();
        keeper.logout().unwrap();
    }

    fn signed(h: &Harness<'static, PdfCraftApp>) -> bool {
        let s = h.state();
        s.session.get(s.views[0].id).is_some_and(|d| d.signatures.iter().any(|x| x.signed))
    }

    #[test]
    #[ignore = "run by a_pkcs11_device_signs_through_the_dialog with SoftHSM set up"]
    fn dialog_checks() {
        let (Some(lib), Some(work)) = (std::env::var_os("PDFCRAFT_TEST_SOFTHSM_LIB"), std::env::var_os("PDFCRAFT_TEST_WORKDIR")) else { return };
        let (lib, work) = (PathBuf::from(lib), PathBuf::from(work));
        set_up_token(&lib);
        let lib_text = lib.to_string_lossy().into_owned();

        // No digital IDs yet: Configure, with a signature creation device.
        let mut h = harness(work.clone());
        h.state_mut().start_signing(0, None, None, None);
        h.run_steps(2);
        assert_eq!(h.state().sign_draft.as_ref().unwrap().step, SignStep::Configure);
        h.get_by_label("Use a signature creation device (PKCS #11 module: smart card, token, CloudSigner for mSzafir)").click();
        h.run_steps(2);
        h.get_by_label("CloudSigner (mSzafir) is found by itself when it is installed: start it and log in before signing.");
        h.state_mut().sign_draft.as_mut().unwrap().new_id.module = lib_text.clone();
        h.run_steps(1);
        h.get_by_label("Continue").click();
        h.run_steps(3);
        assert_eq!(h.state().sign_draft.as_ref().unwrap().error, None);
        assert_eq!(h.state().pkcs11_modules, std::slice::from_ref(&lib_text));
        let entry = h.state().digital_ids.iter().find(|e| e.path.starts_with("pkcs11:")).cloned().expect("the token's identity is listed");
        assert_eq!(entry.name, "Device Signer (UI test)");
        assert_eq!(h.state().sign_draft.as_ref().unwrap().step, SignStep::Choose);
        // The picker's row, by the certificate's name and token.
        h.get_by_label("Device Signer (UI test)");

        // Sign as: a PIN, not a file password.
        h.run_steps(2);
        h.get_by_label("Continue").click();
        h.run_steps(3);
        h.get_by_label("Sign as \"Device Signer (UI test)\"");
        assert_eq!(h.query_all_by_label("Digital ID password").count(), 0);
        h.get_by_label("PIN");
        h.get_by_label("The key is on the device, which signs once it has its PIN.");
        h.get_by_label("Sign").click();
        h.run_steps(3);
        assert_eq!(h.state().sign_draft.as_ref().unwrap().error.as_deref(), Some("Enter the device's PIN."));
        h.state_mut().sign_draft.as_mut().unwrap().password = "000000".into();
        h.get_by_label("Sign").click();
        h.run_steps(3);
        assert_eq!(h.state().sign_draft.as_ref().unwrap().error.as_deref(), Some("The PIN is incorrect."));

        // The right PIN: the token signs on a worker; the app saves the file when it's done.
        h.state_mut().sign_draft.as_mut().unwrap().password = PIN.into();
        h.get_by_label("Sign").click();
        for _ in 0..400 {
            h.run_steps(1);
            if signed(&h) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(signed(&h), "the document was signed and shown");
        assert!(work.join("contract_signed.pdf").is_file());
        let s = h.state();
        let doc = s.session.get(s.views[0].id).unwrap();
        let sig = doc.signatures.iter().find(|x| x.signed).unwrap();
        assert_ne!(sig.status, SignatureStatus::Invalid, "{:?}", sig.details);
        assert_eq!(sig.signer.as_deref(), Some("Device Signer"));

        // The module is kept; the token's identities are listed afresh.
        let settings: serde_json::Value = serde_json::from_str(&h.state().persist()).unwrap();
        assert_eq!(settings["pkcs11_modules"], serde_json::json!([lib_text]));
        assert!(settings["digital_ids"].as_array().unwrap().is_empty());
        let mut restored = PdfCraftApp::new();
        restored.restore(&h.state().persist());
        assert_eq!(restored.pkcs11_modules, std::slice::from_ref(&lib_text));

        // A module named as CloudSigner's says where the approval happens.
        let cloudsigner = work.join("libCloudSignerP11.so");
        std::os::unix::fs::symlink(&lib, &cloudsigner).unwrap();
        let mut h = harness(work.join("cs"));
        h.state_mut().pkcs11_modules = vec![cloudsigner.to_string_lossy().into_owned()];
        h.state_mut().start_signing(0, None, None, None);
        h.run_steps(3);
        assert_eq!(h.state().sign_draft.as_ref().unwrap().step, SignStep::Choose);
        h.get_by_label("Continue").click();
        h.run_steps(3);
        h.get_by_label_contains("enter the OTT code from the mSzafir app in CloudSigner's window");

        // Remove detaches the module the user attached.
        let mut h = harness(work.join("rm"));
        h.state_mut().pkcs11_modules = vec![lib_text.clone()];
        h.state_mut().start_signing(0, None, None, None);
        h.run_steps(3);
        let i = h.state().digital_ids.iter().position(|e| e.path.starts_with("pkcs11:")).unwrap();
        assert!(h.state_mut().remove_digital_id(i));
        assert!(h.state().pkcs11_modules.is_empty());
        assert!(!h.state().digital_ids.iter().any(|e| e.path.starts_with("pkcs11")));
    }
}
