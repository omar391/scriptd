use std::collections::{BTreeMap, HashSet};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

use super::{console_uid, validate_team_identifier, InstallerGrant};

const PACKAGE_STAGE_DIRECTORY: &str = "/Library/Application Support/scriptd/packages";
const MAX_PACKAGE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PACKAGE_COMPONENTS: usize = 128;
const MAX_PACKAGE_DEPTH: usize = 4;
const MAX_PACKAGE_INFO_BYTES: u64 = 1024 * 1024;
const MAX_EXPANDED_METADATA_ENTRIES: usize = 8192;
const PACKAGE_STAGE_MODE: u32 = 0o700;

pub(super) fn install_approved_package(
    package_identifier: &str,
    source_path: &str,
    grants: &[InstallerGrant],
) -> Result<()> {
    let grant = grants
        .iter()
        .find(|grant| {
            grant.package_identifier == package_identifier && grant.method == "package_installer_v1"
        })
        .context("approved package grant is unavailable")?;
    if grant.package_identifier != package_identifier {
        bail!("installer approval does not match the requested package");
    }
    let source = open_regular_package_source(source_path)?;
    let source_metadata = source.metadata().context("inspect opened package source")?;
    if !source_metadata.is_file()
        || source_metadata.uid() != console_uid()?
        || source_metadata.mode() & 0o022 != 0
        || source_metadata.len() == 0
        || source_metadata.len() > MAX_PACKAGE_BYTES
    {
        bail!(
            "package source must be a regular, user-owned, non-writable package within the size limit"
        );
    }

    let stage_root = Path::new(PACKAGE_STAGE_DIRECTORY);
    match DirBuilder::new().mode(0o700).create(stage_root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("create protected package staging directory"),
    }
    let metadata = fs::symlink_metadata(stage_root).context("inspect package staging directory")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
        bail!("package staging directory must be root-owned and accessible only by root");
    }
    let stage_dir = stage_root.join(format!("scriptd-{}", std::process::id()));
    fs::create_dir(&stage_dir).context("create unique protected package transaction directory")?;
    fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o700))?;
    let staged_package = stage_dir.join("approved.pkg");
    let transaction = (|| -> Result<()> {
        let mut staged = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged_package)
            .context("create root-only staged package")?;
        let copied = std::io::copy(&mut (&source).take(MAX_PACKAGE_BYTES + 1), &mut staged)
            .context("copy package into protected staging")?;
        if copied != source_metadata.len() || copied > MAX_PACKAGE_BYTES {
            bail!("staged package size did not match its source");
        }
        staged
            .sync_all()
            .context("flush staged package before verification")?;
        drop(staged);

        verify_package_signature(&staged_package, &grant.publisher_team_identifier)?;
        let package_ids = inspect_package_identifiers(&staged_package, &stage_dir)?;
        if !package_ids.iter().any(|id| id == package_identifier) {
            bail!("package does not contain the approved package identifier");
        }
        for id in &package_ids {
            let component_grant = grants.iter().find(|grant| {
                grant.package_identifier == *id && grant.method == "package_installer_v1"
            }).context("package contains an installer component without its own administrator approval")?;
            if component_grant.publisher_team_identifier != grant.publisher_team_identifier {
                bail!("package component publisher does not match the approved publisher");
            }
        }

        let result = Command::new("/usr/sbin/installer")
            .args([
                "-pkg",
                staged_package
                    .to_str()
                    .context("staged path is not UTF-8")?,
                "-target",
                "/",
            ])
            .output()
            .context("run the fixed macOS package installer operation")?;
        if !result.status.success() {
            let detail: String = String::from_utf8_lossy(&result.stderr)
                .trim()
                .chars()
                .take(2048)
                .collect();
            bail!(
                "macOS package installer failed with status {}; installed components may have changed: {}",
                result.status,
                detail
            );
        }
        Ok(())
    })();
    if let Err(error) = fs::remove_dir_all(&stage_dir) {
        eprintln!("could not remove protected package transaction files: {error}");
    }
    transaction
}

fn open_regular_package_source(source_path: &str) -> Result<fs::File> {
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source_path)
        .context("open package source without following links")?;
    if !source
        .metadata()
        .context("inspect opened package source")?
        .is_file()
    {
        bail!("package source must be a regular file");
    }
    Ok(source)
}

fn verify_package_signature(package: &Path, expected_team: &str) -> Result<()> {
    let signature = Command::new("/usr/sbin/pkgutil")
        .arg("--check-signature")
        .arg(package)
        .output()
        .context("verify package signing chain")?;
    if !signature.status.success() {
        bail!("package signature verification failed");
    }
    let signature_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&signature.stdout),
        String::from_utf8_lossy(&signature.stderr)
    );
    let trusted_certificate = signature_text.contains("trusted by Mac OS X")
        || signature_text.contains("Signed with a trusted timestamp");
    if !signature_text.contains("Developer ID Installer:") || !trusted_certificate {
        bail!("package is not signed by a trusted Developer ID Installer certificate");
    }
    let signer = developer_id_team(&signature_text)
        .context("package signature did not report a Developer ID Installer team identifier")?;
    if signer != expected_team {
        bail!("package publisher does not match the administrator-approved signing team");
    }

    let assessment = Command::new("/usr/sbin/spctl")
        .args(["--assess", "--type", "install", "--verbose=4"])
        .arg(package)
        .output()
        .context("assess package notarization with Gatekeeper")?;
    let assessment_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&assessment.stdout),
        String::from_utf8_lossy(&assessment.stderr)
    );
    if !assessment.status.success() || !assessment_text.contains("Notarized Developer ID") {
        bail!("Gatekeeper did not verify a notarized Developer ID package");
    }
    Ok(())
}

pub(super) fn developer_id_team(output: &str) -> Option<&str> {
    output.lines().find_map(|line| {
        if !line.contains("Developer ID Installer:") {
            return None;
        }
        let open = line.rfind('(')?;
        let close = line[open + 1..].find(')')? + open + 1;
        let team = &line[open + 1..close];
        (validate_team_identifier(team).is_ok()).then_some(team)
    })
}

fn inspect_package_identifiers(package: &Path, stage_dir: &Path) -> Result<Vec<String>> {
    let mut pending = vec![(package.to_path_buf(), 0usize, None)];
    let mut inspected = HashSet::new();
    let mut identifiers = Vec::new();
    let mut expanded_count = 0usize;
    let mut metadata_entries = 0usize;
    let mut distribution_references = Vec::new();
    while let Some((package, depth, expected_identifier)) = pending.pop() {
        let package_identity = package
            .canonicalize()
            .context("resolve package within protected staging")?;
        if !inspected.insert(package_identity) {
            continue;
        }
        if expanded_count >= MAX_PACKAGE_COMPONENTS || depth > MAX_PACKAGE_DEPTH {
            bail!("package contains too many nested installer components");
        }
        let expanded = if package.is_dir() {
            package.clone()
        } else {
            let expanded = stage_dir.join(format!("expanded-{expanded_count}"));
            expand_package(&package, &expanded)?;
            expanded_count += 1;
            expanded
        };
        let identifier_start = identifiers.len();
        let mut nested_packages = Vec::new();
        collect_expanded_metadata(
            &expanded,
            0,
            &mut metadata_entries,
            &mut identifiers,
            &mut nested_packages,
            &mut distribution_references,
        )?;
        let package_identifiers = &identifiers[identifier_start..];
        if let Some(expected) = expected_identifier {
            if !package_identifiers
                .iter()
                .any(|identifier| identifier == &expected)
            {
                bail!(
                    "Distribution package reference does not match its target PackageInfo identifier"
                );
            }
        }
        let mut children = BTreeMap::new();
        for nested in nested_packages {
            let nested = nested
                .canonicalize()
                .context("resolve nested package within protected staging")?;
            children.entry(nested).or_insert(None);
        }
        for (identifier, target) in std::mem::take(&mut distribution_references) {
            match children.entry(target) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(Some(identifier));
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if entry
                        .get()
                        .as_ref()
                        .is_some_and(|existing| existing != &identifier)
                    {
                        bail!(
                            "one Distribution package target has conflicting component identifiers"
                        );
                    }
                    entry.insert(Some(identifier));
                }
            }
        }
        pending.extend(
            children
                .into_iter()
                .map(|(nested, identifier)| (nested, depth + 1, identifier)),
        );
    }
    identifiers.sort();
    identifiers.dedup();
    if identifiers.is_empty() || identifiers.len() > MAX_PACKAGE_COMPONENTS {
        bail!("package metadata did not contain a bounded set of component identifiers");
    }
    Ok(identifiers)
}

fn expand_package(package: &Path, destination: &Path) -> Result<()> {
    let result = Command::new("/usr/sbin/pkgutil")
        .arg("--expand")
        .arg(package)
        .arg(destination)
        .output()
        .context("expand signed installer metadata")?;
    if !result.status.success() {
        bail!("macOS could not expand installer metadata");
    }
    fs::set_permissions(destination, fs::Permissions::from_mode(PACKAGE_STAGE_MODE))
        .context("protect expanded package metadata")?;
    let metadata =
        fs::symlink_metadata(destination).context("inspect expanded package metadata")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
        bail!("expanded package metadata is not protected root-owned data");
    }
    Ok(())
}

fn collect_expanded_metadata(
    directory: &Path,
    depth: usize,
    entries_seen: &mut usize,
    identifiers: &mut Vec<String>,
    nested_packages: &mut Vec<std::path::PathBuf>,
    distribution_references: &mut Vec<(String, std::path::PathBuf)>,
) -> Result<()> {
    if depth > 32 {
        bail!("expanded package metadata exceeds the directory nesting limit");
    }
    for entry in fs::read_dir(directory).context("read expanded package metadata")? {
        *entries_seen += 1;
        if *entries_seen > MAX_EXPANDED_METADATA_ENTRIES {
            bail!("expanded package metadata contains too many entries");
        }
        let entry = entry.context("read expanded package entry")?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).context("inspect expanded package entry")?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() && path.extension().is_some_and(|extension| extension == "pkg") {
            nested_packages.push(path);
            if nested_packages.len() > MAX_PACKAGE_COMPONENTS {
                bail!("package contains too many installer components");
            }
        } else if metadata.is_dir() {
            collect_expanded_metadata(
                &path,
                depth + 1,
                entries_seen,
                identifiers,
                nested_packages,
                distribution_references,
            )?;
        } else if metadata.is_file() && path.file_name().is_some_and(|name| name == "PackageInfo") {
            if metadata.len() == 0 || metadata.len() > MAX_PACKAGE_INFO_BYTES {
                bail!("package component metadata is outside the supported size limit");
            }
            let bytes = fs::read(&path).context("read component PackageInfo metadata")?;
            identifiers.push(parse_package_info_identifier(&bytes)?);
        } else if metadata.is_file() && path.file_name().is_some_and(|name| name == "Distribution")
        {
            if metadata.len() == 0 || metadata.len() > MAX_PACKAGE_INFO_BYTES {
                bail!("product Distribution metadata is outside the supported size limit");
            }
            let bytes = fs::read(&path).context("read product Distribution metadata")?;
            distribution_references.extend(parse_distribution_references(&bytes, directory)?);
        } else if metadata.is_file() && path.extension().is_some_and(|extension| extension == "pkg")
        {
            nested_packages.push(path);
            if nested_packages.len() > MAX_PACKAGE_COMPONENTS {
                bail!("package contains too many installer components");
            }
        }
    }
    Ok(())
}

fn parse_distribution_references(
    xml: &[u8],
    directory: &Path,
) -> Result<Vec<(String, std::path::PathBuf)>> {
    let mut reader = Reader::from_reader(xml);
    let mut buffer = Vec::new();
    let mut current_reference: Option<(String, String)> = None;
    let mut references = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) => {
                validate_distribution_attributes(&element)?;
                let name = element.name();
                let name = local_xml_name(name.as_ref());
                if name == "script" {
                    bail!("product Distribution scripts are not supported");
                }
                if name == "pkg-ref" {
                    let identifier = distribution_reference_identifier(&element)?;
                    current_reference = Some((identifier, String::new()));
                }
            }
            Ok(Event::Empty(element)) => {
                validate_distribution_attributes(&element)?;
                let name = element.name();
                let name = local_xml_name(name.as_ref());
                if name == "script" {
                    bail!("product Distribution scripts are not supported");
                }
                if name == "pkg-ref" {
                    let identifier = distribution_reference_identifier(&element)?;
                    references.push((identifier, None));
                }
            }
            Ok(Event::Text(text)) => {
                if let Some((_, target)) = current_reference.as_mut() {
                    target.push_str(&text.xml_content(XmlVersion::Implicit1_0));
                }
            }
            Ok(Event::CData(text)) => {
                if let Some((_, target)) = current_reference.as_mut() {
                    target.push_str(&text.xml_content(XmlVersion::Implicit1_0));
                }
            }
            Ok(Event::End(element)) if local_xml_name(element.name().as_ref()) == "pkg-ref" => {
                if let Some((identifier, target)) = current_reference.take() {
                    references.push((identifier, Some(target.trim().to_string())));
                }
            }
            // Installer resolves XML references. Dropping them here could
            // authorize a staged decoy instead of the URL Installer reads.
            Ok(Event::GeneralRef(_)) | Ok(Event::DocType(_)) => {
                bail!("product Distribution XML references and DTDs are not supported");
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(error).context("parse product Distribution XML"),
        }
        buffer.clear();
    }

    let mut validated = Vec::new();
    for (identifier, target) in references {
        let Some(target) = target.filter(|target| !target.is_empty()) else {
            continue;
        };
        let Some(target) = target.strip_prefix('#') else {
            bail!("product Distribution package references must use an embedded fragment URL");
        };
        let relative = Path::new(target);
        if target.contains(':')
            || target.contains('\\')
            // Installer interprets pkg-ref text as a URL. Percent escapes,
            // query strings, and non-leading fragments can therefore resolve
            // to a different path than the literal filesystem path below.
            || target.contains('%')
            || target.contains('?')
            || target.contains('#')
            || target.chars().any(char::is_control)
            || relative.is_absolute()
            || !relative
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
            || relative.extension() != Some(std::ffi::OsStr::new("pkg"))
        {
            bail!("product Distribution contains an external or unsafe package reference");
        }
        let staging_root = directory
            .canonicalize()
            .context("resolve protected expanded package directory")?;
        let mut current = staging_root.clone();
        for component in relative.components() {
            let std::path::Component::Normal(component) = component else {
                bail!("product Distribution package reference escapes protected staging");
            };
            current.push(component);
            let metadata = fs::symlink_metadata(&current).context(
                "resolve product Distribution package reference inside protected staging",
            )?;
            if metadata.file_type().is_symlink() {
                bail!("product Distribution package references may not traverse symlinks");
            }
        }
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_file() && !metadata.is_dir() {
            bail!("product Distribution reference is not a staged package file or directory");
        }
        let canonical_target = current.canonicalize()?;
        if !canonical_target.starts_with(&staging_root) {
            bail!("product Distribution package reference escapes protected staging");
        }
        validated.push((identifier, canonical_target));
    }
    Ok(validated)
}

fn local_xml_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn distribution_reference_identifier(
    element: &quick_xml::events::BytesStart<'_>,
) -> Result<String> {
    let mut identifier = None;
    for attribute in element.attributes() {
        let attribute = attribute.context("parse Distribution package reference attribute")?;
        if attribute.key.as_ref() == "url" {
            bail!("Distribution package URL attributes are not supported");
        }
        if attribute.key.as_ref() == "id" {
            if identifier.is_some() {
                bail!("Distribution package reference has multiple identifiers");
            }
            identifier = Some(
                attribute
                    .normalized_value(XmlVersion::Implicit1_0)
                    .context("decode Distribution package reference identifier")?
                    .into_owned(),
            );
        }
    }
    let identifier =
        identifier.context("Distribution package reference is missing its identifier")?;
    if identifier.is_empty()
        || identifier.len() > 255
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!("Distribution package reference identifier is invalid");
    }
    Ok(identifier)
}

fn validate_distribution_attributes(element: &quick_xml::events::BytesStart<'_>) -> Result<()> {
    for attribute in element.attributes() {
        let attribute = attribute.context("parse product Distribution attribute")?;
        let name = local_xml_name(attribute.key.as_ref());
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .context("decode Distribution attribute")?;
        match name {
            "script" | "onConclusionScript" => {
                bail!("product Distribution scripts are not supported")
            }
            "selected" | "enabled" | "visible" => {
                if !matches!(value.as_ref(), "true" | "false") {
                    bail!("product Distribution Boolean attributes must be literal values");
                }
            }
            "require-scripts" => {
                if value != "false" {
                    bail!("product Distribution scripts must be disabled");
                }
            }
            "allow-external-scripts" => {
                if value != "false" {
                    bail!("product Distribution external scripts must be disabled");
                }
            }
            "onConclusion" => {
                if value != "none" {
                    bail!("product Distribution conclusion actions are not supported");
                }
            }
            "minSpecVersion" => {
                if value.is_empty()
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.')
                {
                    bail!("product Distribution minimum specification version is invalid");
                }
            }
            "customize" => {
                if !matches!(value.as_ref(), "always" | "never" | "upgrade") {
                    bail!("product Distribution customization mode is unsupported");
                }
            }
            "hostArchitectures" => {
                if value.is_empty()
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b',' | b'_' | b'-' | b'.')
                    })
                {
                    bail!("product Distribution host architecture list is invalid");
                }
            }
            "installKBytes" | "updateKBytes" => {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    bail!("product Distribution install size must be a literal integer");
                }
            }
            "id" | "version" | "choice" => {
                if value.is_empty()
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
                {
                    bail!("product Distribution identifier attribute is invalid");
                }
            }
            _ => bail!("unsupported product Distribution attribute: {name}"),
        }
    }
    Ok(())
}

fn parse_package_info_identifier(xml: &[u8]) -> Result<String> {
    let mut reader = Reader::from_reader(xml);
    let mut buffer = Vec::new();
    let mut identifiers = Vec::new();
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::Start(element)) | Ok(Event::Empty(element))
                if element.name().as_ref() == "pkg-info" =>
            {
                for attribute in element.attributes() {
                    let attribute = attribute.context("parse PackageInfo attribute")?;
                    if attribute.key.as_ref() == "identifier" {
                        identifiers.push(
                            attribute
                                .normalized_value(XmlVersion::Implicit1_0)
                                .context("decode PackageInfo identifier")?
                                .into_owned(),
                        );
                    }
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(error).context("parse PackageInfo XML"),
        }
        buffer.clear();
    }
    if identifiers.len() != 1 {
        bail!("PackageInfo must contain exactly one package identifier");
    }
    let identifier = identifiers.remove(0);
    if identifier.is_empty()
        || identifier.len() > 255
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        bail!("PackageInfo contains an invalid package identifier");
    }
    Ok(identifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn fifo_package_source_is_rejected_without_waiting_for_a_writer() {
        let directory = tempfile::tempdir().expect("create isolated package source directory");
        let path = directory.path().join("source.pkg");
        let path_c = CString::new(path.as_os_str().as_encoded_bytes()).expect("encode FIFO path");
        let result = unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) };
        assert_eq!(result, 0, "create isolated FIFO");

        let error = open_regular_package_source(path.to_str().expect("UTF-8 temp path"))
            .expect_err("FIFO must be rejected");
        assert!(error.to_string().contains("regular file"));
    }

    #[test]
    fn package_info_reads_the_authoritative_identifier_attribute() {
        let xml = br#"<?xml version="1.0"?><pkg-info identifier="com.vendor.agent.pkg" version="1.2" format-version="2"/>"#;
        assert_eq!(
            parse_package_info_identifier(xml).expect("read PackageInfo identifier"),
            "com.vendor.agent.pkg"
        );
    }

    #[test]
    fn package_info_rejects_missing_or_ambiguous_identifiers() {
        assert!(parse_package_info_identifier(b"<pkg-info version=\"1\"/>").is_err());
        assert!(parse_package_info_identifier(
            b"<pkg-info identifier=\"com.vendor.one\"/><pkg-info identifier=\"com.vendor.two\"/>"
        )
        .is_err());
        assert!(
            parse_package_info_identifier(b"<Package>com.vendor.display-name</Package>").is_err()
        );
    }

    #[test]
    fn distribution_references_must_resolve_to_local_staged_packages() {
        let directory = tempfile::tempdir().expect("create protected metadata fixture");
        let component = directory.path().join("component.pkg");
        fs::create_dir(&component).expect("create expanded component package directory");
        fs::write(
            component.join("PackageInfo"),
            b"<pkg-info identifier=\"com.vendor.component.pkg\"/>",
        )
        .expect("write expanded component metadata");
        let distribution = br#"<installer-gui-script><pkg-ref id="com.vendor.component.pkg" version="1"/><pkg-ref id="com.vendor.component.pkg">#component.pkg</pkg-ref></installer-gui-script>"#;
        let references = parse_distribution_references(distribution, directory.path())
            .expect("accept a local reference to an expanded component package");
        assert_eq!(references.len(), 1);
        assert_eq!(references[0].0, "com.vendor.component.pkg");
        assert_eq!(
            references[0].1,
            component.canonicalize().expect("canonical component path")
        );

        // Installer resolves ordinary relative URLs beside the product archive,
        // not from the expanded staging directory inspected by this validator.
        let ordinary_relative = br#"<installer-gui-script><pkg-ref id="com.vendor.component.pkg">component.pkg</pkg-ref></installer-gui-script>"#;
        assert!(parse_distribution_references(ordinary_relative, directory.path()).is_err());

        let external = br#"<installer-gui-script><pkg-ref id="com.vendor.component.pkg">file:///tmp/external.pkg</pkg-ref></installer-gui-script>"#;
        assert!(parse_distribution_references(external, directory.path()).is_err());
        let url_attribute = br#"<installer-gui-script><pkg-ref id="com.vendor.component.pkg" url="https://vendor.example/component.pkg"/></installer-gui-script>"#;
        assert!(parse_distribution_references(url_attribute, directory.path()).is_err());
        let escaping = br#"<installer-gui-script><pkg-ref id="com.vendor.component.pkg">../component.pkg</pkg-ref></installer-gui-script>"#;
        assert!(parse_distribution_references(escaping, directory.path()).is_err());

        // A literal decoy must not make Installer's percent-decoded parent
        // traversal appear to stay inside protected staging.
        let encoded_decoy = directory.path().join("%2e%2e/outside.pkg");
        fs::create_dir_all(encoded_decoy.parent().expect("encoded decoy parent"))
            .expect("create encoded traversal decoy parent");
        fs::write(&encoded_decoy, b"decoy").expect("create encoded traversal decoy");
        let encoded_traversal = br#"<installer-gui-script><pkg-ref id="com.vendor.component.pkg">%2e%2e/outside.pkg</pkg-ref></installer-gui-script>"#;
        assert!(parse_distribution_references(encoded_traversal, directory.path()).is_err());
        let query = br#"<installer-gui-script><pkg-ref id="com.vendor.component.pkg">component.pkg?download=1</pkg-ref></installer-gui-script>"#;
        assert!(parse_distribution_references(query, directory.path()).is_err());

        let external = tempfile::tempdir().expect("create external package directory");
        fs::create_dir(external.path().join("component.pkg")).expect("create external component");
        #[cfg(unix)]
        std::os::unix::fs::symlink(external.path(), directory.path().join("linked-components"))
            .expect("create symlinked ancestor fixture");
        #[cfg(unix)]
        {
            let through_symlink = br#"<installer-gui-script><pkg-ref id="com.vendor.component.pkg">linked-components/component.pkg</pkg-ref></installer-gui-script>"#;
            assert!(parse_distribution_references(through_symlink, directory.path()).is_err());
        }
    }

    #[test]
    fn distribution_scripts_are_rejected() {
        let directory = tempfile::tempdir().expect("create metadata fixture");
        let distribution = br#"<installer-gui-script><script>system.run('/tmp/unapproved')</script></installer-gui-script>"#;
        assert!(parse_distribution_references(distribution, directory.path()).is_err());
        let namespaced = br#"<installer-gui-script xmlns:x="urn:test"><x:script>unapproved</x:script></installer-gui-script>"#;
        assert!(parse_distribution_references(namespaced, directory.path()).is_err());
        let script_attribute = br#"<installer-gui-script><installation-check script="system.run('unapproved') == 0"/></installer-gui-script>"#;
        assert!(parse_distribution_references(script_attribute, directory.path()).is_err());
        let external_scripts = br#"<installer-gui-script allow-external-scripts="true"/>"#;
        assert!(parse_distribution_references(external_scripts, directory.path()).is_err());
        for expression in [
            br#"<installer-gui-script><choice id="main" selected="(true, false)"/></installer-gui-script>"#.as_slice(),
            br#"<installer-gui-script><choice id="main" enabled="system.run('unapproved') == 0"/></installer-gui-script>"#.as_slice(),
            br#"<installer-gui-script><choice id="main" visible="(true, false)"/></installer-gui-script>"#.as_slice(),
            br#"<installer-gui-script><pkg-ref id="com.vendor.component.pkg" onConclusionScript="system.run('unapproved')"/></installer-gui-script>"#.as_slice(),
        ] {
            assert!(parse_distribution_references(expression, directory.path()).is_err());
        }
        assert!(parse_distribution_references(
            br#"<installer-gui-script><choice id="main" selected="true" enabled="false" visible="true"/></installer-gui-script>"#,
            directory.path(),
        )
        .is_ok());
        assert!(parse_distribution_references(
            br#"<installer-gui-script><options customize="never" require-scripts="false"/></installer-gui-script>"#,
            directory.path(),
        )
        .is_ok());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn productbuild_expansion_resolves_fragment_reference_to_component_metadata() {
        let directory = tempfile::tempdir().expect("create product package fixture");
        let payload = directory.path().join("payload");
        fs::create_dir_all(payload.join("private/tmp/bridge-fixture"))
            .expect("create package payload");
        fs::write(
            payload.join("private/tmp/bridge-fixture/marker"),
            b"fixture",
        )
        .expect("write package payload fixture");
        let component = directory.path().join("component.pkg");
        let status = Command::new("/usr/bin/pkgbuild")
            .args(["--root"])
            .arg(&payload)
            .args([
                "--identifier",
                "com.vendor.component.pkg",
                "--version",
                "1.0",
                "--install-location",
                "/",
            ])
            .arg(&component)
            .status()
            .expect("run unprivileged pkgbuild fixture creation");
        assert!(status.success(), "pkgbuild fixture creation failed");
        let product = directory.path().join("product.pkg");
        let status = Command::new("/usr/bin/productbuild")
            .arg("--package")
            .arg(&component)
            .arg(&product)
            .status()
            .expect("run unprivileged productbuild fixture creation");
        assert!(status.success(), "productbuild fixture creation failed");
        let expanded = directory.path().join("expanded");
        let status = Command::new("/usr/sbin/pkgutil")
            .arg("--expand")
            .arg(&product)
            .arg(&expanded)
            .status()
            .expect("run unprivileged pkgutil fixture expansion");
        assert!(status.success(), "pkgutil fixture expansion failed");

        let distribution = fs::read(expanded.join("Distribution"))
            .expect("read productbuild Distribution fixture");
        let references = parse_distribution_references(&distribution, &expanded)
            .expect("resolve productbuild fragment-style package reference");
        assert_eq!(references.len(), 1);
        assert_eq!(references[0].0, "com.vendor.component.pkg");
        assert_eq!(
            references[0].1,
            expanded
                .join("component.pkg")
                .canonicalize()
                .expect("canonical expanded component path")
        );

        let expression_packages = directory.path().join("expression-packages");
        fs::create_dir(&expression_packages).expect("create expression package inputs");
        fs::copy(&component, expression_packages.join("component.pkg"))
            .expect("copy flat component package for expression fixture");
        let expression_distribution = directory.path().join("expression-Distribution");
        fs::write(
            &expression_distribution,
            br#"<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
  <title>Distribution expression regression</title>
  <options customize="always"/>
  <choices-outline><line choice="main"/></choices-outline>
  <choice id="main" selected="(true, false)"><pkg-ref id="com.vendor.component.pkg"/></choice>
  <pkg-ref id="com.vendor.component.pkg" version="1.0" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>"#,
        )
        .expect("write installer-valid inline choice expression fixture");
        let expression_product = directory.path().join("expression-product.pkg");
        let status = Command::new("/usr/bin/productbuild")
            .arg("--distribution")
            .arg(&expression_distribution)
            .arg("--package-path")
            .arg(&expression_packages)
            .arg(&expression_product)
            .status()
            .expect("build installer-valid inline choice expression product");
        assert!(
            status.success(),
            "expression product fixture creation failed"
        );
        let expression_expanded = directory.path().join("expression-expanded");
        let status = Command::new("/usr/sbin/pkgutil")
            .arg("--expand")
            .arg(&expression_product)
            .arg(&expression_expanded)
            .status()
            .expect("expand inline choice expression product");
        assert!(status.success(), "expression product expansion failed");
        let expression_distribution = fs::read(expression_expanded.join("Distribution"))
            .expect("read expanded inline choice expression Distribution");
        assert!(
            parse_distribution_references(&expression_distribution, &expression_expanded).is_err()
        );

        let mut entries = 0;
        let mut identifiers = Vec::new();
        let mut nested = Vec::new();
        let mut child_references = Vec::new();
        collect_expanded_metadata(
            &references[0].1,
            0,
            &mut entries,
            &mut identifiers,
            &mut nested,
            &mut child_references,
        )
        .expect("inspect expanded component package metadata");
        assert_eq!(identifiers, ["com.vendor.component.pkg"]);

        // Preserve an embedded decoy whose path matches the text obtained by
        // incorrectly dropping the character reference from an external URL.
        let decoy = expanded.join("file/tmp/external.pkg");
        fs::create_dir_all(decoy.parent().expect("decoy parent"))
            .expect("create embedded decoy parent");
        fs::rename(expanded.join("component.pkg"), &decoy)
            .expect("move expanded component to embedded decoy path");
        let distribution = String::from_utf8(distribution).expect("UTF-8 Distribution fixture");
        for (index, reference) in [
            "file&#58;///tmp/external.pkg",
            "file&#x3a;///tmp/external.pkg",
        ]
        .into_iter()
        .enumerate()
        {
            fs::write(
                expanded.join("Distribution"),
                distribution.replace("#component.pkg", reference),
            )
            .expect("write encoded external reference");
            let encoded_product = directory.path().join(format!("encoded-{index}.pkg"));
            let status = Command::new("/usr/sbin/pkgutil")
                .arg("--flatten")
                .arg(&expanded)
                .arg(&encoded_product)
                .status()
                .expect("flatten encoded external-reference product");
            assert!(status.success(), "encoded product flattening failed");
            let encoded_expanded = directory.path().join(format!("encoded-expanded-{index}"));
            let status = Command::new("/usr/sbin/pkgutil")
                .arg("--expand")
                .arg(&encoded_product)
                .arg(&encoded_expanded)
                .status()
                .expect("expand encoded external-reference product");
            assert!(status.success(), "encoded product expansion failed");
            let encoded_distribution = fs::read(encoded_expanded.join("Distribution"))
                .expect("read preserved encoded Distribution");
            assert!(String::from_utf8_lossy(&encoded_distribution).contains(reference));
            assert!(encoded_expanded
                .join("file/tmp/external.pkg/PackageInfo")
                .is_file());
            let error = parse_distribution_references(&encoded_distribution, &encoded_expanded)
                .expect_err("encoded external URL must not authorize an embedded decoy");
            assert!(error.to_string().contains("XML references"));
        }
    }

    #[test]
    #[ignore = "requires a signed notarized test package and disposable macOS runner"]
    fn isolated_signed_package_installs_only_with_matching_publisher_and_component_grant() {
        let package_path =
            std::env::var("SCRIPTD_INSTALLER_SMOKE_PACKAGE").expect("isolated smoke package path");
        let publisher = std::env::var("SCRIPTD_INSTALLER_SMOKE_PUBLISHER")
            .expect("isolated smoke publisher team");
        let package_identifier = "com.astronlab.scriptd.installer-smoke.pkg";
        let marker = Path::new("/private/tmp/scriptd-installer-smoke/marker");
        let package_metadata = fs::metadata(&package_path).expect("inspect signed smoke package");
        assert_eq!(
            package_metadata.uid(),
            console_uid().expect("find disposable runner console user")
        );

        let grant = InstallerGrant {
            app_identity: super::super::Identity {
                team_identifier: publisher.clone(),
                bundle_identifier: "com.astronlab.scriptd".into(),
            },
            publisher_team_identifier: publisher,
            package_identifier: package_identifier.into(),
            method: "package_installer_v1".into(),
        };
        let dependency_grant = InstallerGrant {
            package_identifier: "com.astronlab.scriptd.installer-smoke.dependency.pkg".into(),
            ..grant.clone()
        };
        let parent = Path::new("/Library/Application Support/scriptd");
        fs::create_dir_all(parent).expect("prepare protected parent on disposable runner");
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
            .expect("protect package staging parent");
        if marker.exists() {
            fs::remove_file(marker).expect("remove stale disposable-runner marker");
        }

        install_approved_package(
            package_identifier,
            &package_path,
            &[grant.clone(), dependency_grant.clone()],
        )
        .expect("install signed notarized package with matching component approvals");
        assert!(
            marker.is_file(),
            "approved package did not install its marker"
        );

        let wrong_publisher = InstallerGrant {
            publisher_team_identifier: "WRONGTEAM1".into(),
            ..grant.clone()
        };
        assert!(install_approved_package(
            package_identifier,
            &package_path,
            &[wrong_publisher, dependency_grant]
        )
        .is_err());
        assert!(install_approved_package(package_identifier, &package_path, &[grant]).is_err());
        assert!(install_approved_package(package_identifier, &package_path, &[]).is_err());
    }
}
