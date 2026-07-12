use std::collections::HashMap;
#[cfg(not(test))]
use std::fs;
use std::io::Write;
#[cfg(not(test))]
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[cfg(test)]
use once_cell::sync::Lazy;
use rpassword::read_password;
#[cfg(not(test))]
use security_framework::passwords::set_generic_password as keychain_set_generic_password;
pub const SCRIPTD_ADMIN_SERVICE: &str = "ScriptdAdmin";
#[cfg(not(test))]
const SECURITY_COMMAND: &str = "/usr/bin/security";
const KEYCHAIN_NAMESPACE: &str = "scriptd";
#[cfg(not(test))]
const KEYCHAIN_COMMENT: &str = "scriptd managed credential";

#[cfg(test)]
static TEST_CREDENTIALS: Lazy<std::sync::Mutex<HashMap<String, String>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

fn first_nonempty(values: impl IntoIterator<Item = Option<String>>) -> String {
    values
        .into_iter()
        .flatten()
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}

fn resolve_user_name(
    user: Option<String>,
    logname: Option<String>,
    id_output: Option<String>,
) -> String {
    first_nonempty([id_output, user, logname])
}

pub fn current_user() -> String {
    let user = std::env::var("USER").ok();
    let logname = std::env::var("LOGNAME").ok();
    let id_output = Command::new("/usr/bin/id")
        .args(["-un"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned());
    resolve_user_name(user, logname, id_output)
}

pub fn scriptd_service(scope: &str, name: &str) -> String {
    format!("{scope}:{name}")
}

fn credential_key(service: &str, account: &str) -> String {
    format!("{service}\n{account}")
}

fn keychain_service(service: &str) -> String {
    format!("{KEYCHAIN_NAMESPACE}:{service}")
}

#[cfg(not(test))]
fn file_store_path() -> Option<PathBuf> {
    std::env::var_os("SCRIPTD_CREDENTIALS_FILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(not(test))]
fn file_store_read(path: &PathBuf) -> HashMap<String, String> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str::<HashMap<String, String>>(&text).ok())
        .unwrap_or_default()
}

#[cfg(not(test))]
fn file_store_write(path: &PathBuf, values: &HashMap<String, String>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(values)?)?;
    Ok(())
}

pub fn find_generic_password(service: &str, account: &str) -> anyhow::Result<Option<String>> {
    #[cfg(test)]
    {
        let values = TEST_CREDENTIALS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        Ok(values.get(&credential_key(service, account)).cloned())
    }

    #[cfg(not(test))]
    {
        if let Some(path) = file_store_path() {
            let values = file_store_read(&path);
            return Ok(values.get(&credential_key(service, account)).cloned());
        }

        let keychain_service = keychain_service(service);
        let output = Command::new(SECURITY_COMMAND)
            .args([
                "find-generic-password",
                "-s",
                &keychain_service,
                "-a",
                account,
                "-j",
                KEYCHAIN_COMMENT,
                "-w",
            ])
            .output()?;
        if !output.status.success() {
            return Ok(None);
        }
        let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok((!password.is_empty()).then_some(password))
    }
}

pub fn store_generic_password(service: &str, account: &str, password: &str) -> anyhow::Result<()> {
    #[cfg(test)]
    {
        let mut values = TEST_CREDENTIALS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        values.insert(credential_key(service, account), password.to_string());
        Ok(())
    }

    #[cfg(not(test))]
    {
        if let Some(path) = file_store_path() {
            let mut values = file_store_read(&path);
            values.insert(credential_key(service, account), password.to_string());
            return file_store_write(&path, &values);
        }

        let keychain_service = keychain_service(service);
        let existing = Command::new(SECURITY_COMMAND)
            .args([
                "find-generic-password",
                "-s",
                &keychain_service,
                "-a",
                account,
                "-j",
                KEYCHAIN_COMMENT,
            ])
            .output()?;
        if !existing.status.success() {
            // Create an empty item with a stable Apple-signed reader. The real
            // secret is written in-process below, so it never appears in argv.
            let output = Command::new(SECURITY_COMMAND)
                .args([
                    "add-generic-password",
                    "-s",
                    &keychain_service,
                    "-a",
                    account,
                    "-j",
                    KEYCHAIN_COMMENT,
                    "-T",
                    SECURITY_COMMAND,
                    "-w",
                    "",
                ])
                .output()?;
            if !output.status.success() {
                let raced_item = Command::new(SECURITY_COMMAND)
                    .args([
                        "find-generic-password",
                        "-s",
                        &keychain_service,
                        "-a",
                        account,
                        "-j",
                        KEYCHAIN_COMMENT,
                    ])
                    .output()?;
                if raced_item.status.success() {
                    keychain_set_generic_password(&keychain_service, account, password.as_bytes())?;
                    return Ok(());
                }
                let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
                anyhow::bail!(
                    "security add-generic-password failed{}",
                    if message.is_empty() {
                        String::new()
                    } else {
                        format!(": {message}")
                    }
                );
            }
        }
        keychain_set_generic_password(&keychain_service, account, password.as_bytes())?;
        Ok(())
    }
}

pub fn delete_generic_password(service: &str, account: &str) -> anyhow::Result<()> {
    #[cfg(test)]
    {
        let mut values = TEST_CREDENTIALS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        values.remove(&credential_key(service, account));
        Ok(())
    }

    #[cfg(not(test))]
    {
        if let Some(path) = file_store_path() {
            let mut values = file_store_read(&path);
            values.remove(&credential_key(service, account));
            return file_store_write(&path, &values);
        }

        let keychain_service = keychain_service(service);
        let output = Command::new(SECURITY_COMMAND)
            .args([
                "delete-generic-password",
                "-s",
                &keychain_service,
                "-a",
                account,
            ])
            .output()?;
        if output.status.success() || output.status.code() == Some(44) {
            return Ok(());
        }
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!(
            "security delete-generic-password failed{}",
            if message.is_empty() {
                String::new()
            } else {
                format!(": {message}")
            }
        )
    }
}

pub fn admin_password() -> anyhow::Result<Option<String>> {
    let account = admin_account()?;
    find_generic_password(SCRIPTD_ADMIN_SERVICE, &account)
}

fn admin_account() -> anyhow::Result<String> {
    let account = current_user();
    if account.is_empty() {
        anyhow::bail!("could not resolve the current user for admin credential access");
    }
    Ok(account)
}

pub fn verify_admin_password(password: &str) -> bool {
    let mut command = Command::new("sudo");
    command
        .args(["-S", "-k", "-v"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let Ok(mut child) = command.spawn() else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(format!("{password}\n").as_bytes()).is_err() {
            return false;
        }
        let _ = stdin.flush();
    }

    child.wait().map(|status| status.success()).unwrap_or(false)
}

pub fn admin_password_or_prompt() -> anyhow::Result<String> {
    if let Some(password) = admin_password()? {
        if verify_admin_password(&password) {
            return Ok(password);
        }
        let _ = delete_admin_password();
    }

    for _ in 0..3 {
        eprintln!("Enter your sudo password for scriptd:");
        let password =
            read_password().map_err(|error| anyhow::anyhow!("failed to read password: {error}"))?;
        if !verify_admin_password(&password) {
            eprintln!("Password verification failed");
            continue;
        }
        store_admin_password(&password)?;
        return Ok(password);
    }

    anyhow::bail!("could not verify password after 3 attempts")
}

pub fn store_admin_password(password: &str) -> anyhow::Result<()> {
    let account = admin_account()?;
    store_generic_password(SCRIPTD_ADMIN_SERVICE, &account, password)
}

pub fn delete_admin_password() -> anyhow::Result<()> {
    let account = admin_account()?;
    delete_generic_password(SCRIPTD_ADMIN_SERVICE, &account)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scriptd_service_names_are_stable() {
        assert_eq!(scriptd_service("mwifi", "Office"), "mwifi:Office");
        assert_eq!(keychain_service("mwifi:Office"), "scriptd:mwifi:Office");
    }

    #[test]
    fn current_user_falls_back_when_launchd_does_not_set_user() {
        assert_eq!(
            resolve_user_name(None, None, Some("omar\n".to_string())),
            "omar"
        );
        assert_eq!(
            resolve_user_name(Some("  ".to_string()), Some("omar".to_string()), None),
            "omar"
        );
        assert_eq!(
            resolve_user_name(
                Some("wrong".to_string()),
                Some("wrong".to_string()),
                Some("omar\n".to_string())
            ),
            "omar"
        );
    }
}
