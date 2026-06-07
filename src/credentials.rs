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
use security_framework::passwords::{
    delete_generic_password as keychain_delete_generic_password,
    get_generic_password as keychain_get_generic_password,
    set_generic_password as keychain_set_generic_password,
};

pub const SCRIPTD_ADMIN_SERVICE: &str = "ScriptdAdmin";
pub const LEGACY_BREW_ADMIN_SERVICE: &str = "BrewAutoUpdate";

#[cfg(test)]
static TEST_CREDENTIALS: Lazy<std::sync::Mutex<HashMap<String, String>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

pub fn current_user() -> String {
    std::env::var("USER").unwrap_or_default()
}

pub fn scriptd_service(scope: &str, name: &str) -> String {
    format!("scriptd-{scope}:{name}")
}

fn credential_key(service: &str, account: &str) -> String {
    format!("{service}\n{account}")
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

        let Ok(password) = keychain_get_generic_password(service, account) else {
            return Ok(None);
        };
        let password = String::from_utf8_lossy(&password).trim().to_string();
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

        let _ = keychain_delete_generic_password(service, account);
        keychain_set_generic_password(service, account, password.as_bytes())?;
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

        let _ = keychain_delete_generic_password(service, account);
        Ok(())
    }
}

pub fn admin_password(legacy_service: Option<&str>) -> anyhow::Result<Option<String>> {
    let account = current_user();
    if let Some(password) = find_generic_password(SCRIPTD_ADMIN_SERVICE, &account)? {
        if let Some(legacy_service) =
            legacy_service.filter(|service| *service != SCRIPTD_ADMIN_SERVICE)
        {
            if find_generic_password(legacy_service, &account)?.is_none() {
                let _ = store_generic_password(legacy_service, &account, &password);
            }
        }
        return Ok(Some(password));
    }

    if let Some(legacy_service) = legacy_service {
        if let Some(password) = find_generic_password(legacy_service, &account)? {
            let _ = store_generic_password(SCRIPTD_ADMIN_SERVICE, &account, &password);
            return Ok(Some(password));
        }
    }

    Ok(None)
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

pub fn admin_password_or_prompt(legacy_service: Option<&str>) -> anyhow::Result<String> {
    if let Some(password) = admin_password(legacy_service)? {
        if verify_admin_password(&password) {
            return Ok(password);
        }
        let _ = delete_admin_password(legacy_service);
    }

    for _ in 0..3 {
        eprintln!("Enter your sudo password for scriptd:");
        let password =
            read_password().map_err(|error| anyhow::anyhow!("failed to read password: {error}"))?;
        if !verify_admin_password(&password) {
            eprintln!("Password verification failed");
            continue;
        }
        store_admin_password(&password, legacy_service)?;
        return Ok(password);
    }

    anyhow::bail!("could not verify password after 3 attempts")
}

pub fn store_admin_password(password: &str, legacy_service: Option<&str>) -> anyhow::Result<()> {
    let account = current_user();
    store_generic_password(SCRIPTD_ADMIN_SERVICE, &account, password)?;
    if let Some(legacy_service) = legacy_service.filter(|service| *service != SCRIPTD_ADMIN_SERVICE)
    {
        store_generic_password(legacy_service, &account, password)?;
    }
    Ok(())
}

pub fn delete_admin_password(legacy_service: Option<&str>) -> anyhow::Result<()> {
    let account = current_user();
    let _ = delete_generic_password(SCRIPTD_ADMIN_SERVICE, &account);
    if let Some(legacy_service) = legacy_service.filter(|service| *service != SCRIPTD_ADMIN_SERVICE)
    {
        let _ = delete_generic_password(legacy_service, &account);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scriptd_service_names_are_stable() {
        assert_eq!(scriptd_service("wifi", "Office"), "scriptd-wifi:Office");
        assert_eq!(
            scriptd_service("better-wifi", "Office"),
            "scriptd-better-wifi:Office"
        );
    }
}
