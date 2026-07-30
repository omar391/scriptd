use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use sysinfo::{Pid, ProcessesToUpdate, System};

use super::{ApplicationNetworkSample, SensorSnapshot};

#[derive(Debug)]
pub struct SensorSuite {
    system: System,
    last_visibility: Option<VisibilityCache>,
}

#[derive(Debug)]
struct VisibilityCache {
    scanned_at: Instant,
    requested_ssids: BTreeSet<String>,
    visible_ssids: Option<BTreeSet<String>>,
    error: Option<String>,
}

#[derive(Debug)]
pub struct WifiEventWatcher {
    child: Child,
    reader: Option<JoinHandle<()>>,
}

impl Drop for WifiEventWatcher {
    fn drop(&mut self) {
        let _ = self.child.kill();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let _ = self.child.wait();
    }
}

impl Default for SensorSuite {
    fn default() -> Self {
        Self {
            system: System::new_all(),
            last_visibility: None,
        }
    }
}

impl SensorSuite {
    fn should_scan_visibility(&self, ssids: &BTreeSet<String>) -> bool {
        self.last_visibility.as_ref().is_none_or(|cache| {
            &cache.requested_ssids != ssids || cache.scanned_at.elapsed() >= Duration::from_secs(30)
        })
    }

    pub fn spawn_wifi_event_watcher(
        sender: tokio::sync::mpsc::UnboundedSender<()>,
    ) -> Option<WifiEventWatcher> {
        let script = r#"
import CoreWLAN
import Darwin
import Foundation

final class ScriptdWiFiDelegate: NSObject, CWEventDelegate {
    private func changed() {
        print("changed")
        fflush(stdout)
    }
    func powerStateDidChangeForWiFiInterface(withName interfaceName: String) { changed() }
    func ssidDidChangeForWiFiInterface(withName interfaceName: String) { changed() }
    func linkDidChangeForWiFiInterface(withName interfaceName: String) { changed() }
    func scanCacheUpdatedForWiFiInterface(withName interfaceName: String) { changed() }
}

let client = CWWiFiClient.shared()
let delegate = ScriptdWiFiDelegate()
client.delegate = delegate
try? client.startMonitoringEvent(with: .powerDidChange)
try? client.startMonitoringEvent(with: .ssidDidChange)
try? client.startMonitoringEvent(with: .linkDidChange)
try? client.startMonitoringEvent(with: .scanCacheUpdated)
RunLoop.main.run()
"#;
        let mut child = Command::new("/usr/bin/swift")
            .args(["-e", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        };
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.is_err() || sender.send(()).is_err() {
                    break;
                }
            }
        });
        Some(WifiEventWatcher {
            child,
            reader: Some(reader),
        })
    }

    pub fn snapshot(
        &mut self,
        ssids: &BTreeSet<String>,
        applications: &BTreeSet<String>,
        needs_wifi_power: bool,
    ) -> SensorSnapshot {
        let mut wifi = if ssids.is_empty() && !needs_wifi_power {
            Default::default()
        } else {
            crate::modules::wifi_trigger_link_snapshot()
        };
        if !ssids.is_empty() {
            if wifi.power == Some(false) {
                self.last_visibility = None;
                wifi.visible_ssids = None;
                wifi.error = Some("wifi visibility unavailable while power is off".to_string());
            } else {
                let should_scan = self.should_scan_visibility(ssids);
                if should_scan {
                    let (visible, error) = crate::modules::wifi_trigger_visibility_snapshot(
                        &ssids.iter().cloned().collect::<Vec<_>>(),
                    );
                    self.last_visibility = Some(VisibilityCache {
                        scanned_at: Instant::now(),
                        requested_ssids: ssids.clone(),
                        visible_ssids: visible,
                        error,
                    });
                }
                if let Some(cache) = &self.last_visibility {
                    wifi.visible_ssids = cache.visible_ssids.clone();
                    if cache.error.is_some() {
                        wifi.error = cache.error.clone();
                    }
                }
            }
        }

        let (application_network, network_error) = if applications.is_empty() {
            (Vec::new(), None)
        } else {
            self.system.refresh_processes(ProcessesToUpdate::All, true);
            match sample_external_network_bytes_by_pid() {
                Ok(bytes_by_pid) => {
                    let processes = bytes_by_pid.into_iter().filter_map(|(pid, bytes)| {
                        self.system
                            .process(Pid::from_u32(pid))
                            .and_then(|process| process.exe())
                            .map(|executable| (executable, bytes))
                    });
                    (aggregate_application_network(applications, processes), None)
                }
                Err(error) => (Vec::new(), Some(error)),
            }
        };

        SensorSnapshot {
            wifi,
            application_network,
            network_error,
        }
    }
}

fn sample_external_network_bytes_by_pid() -> Result<BTreeMap<u32, u64>, String> {
    let output = Command::new("/usr/bin/nettop")
        .args([
            "-n",
            "-P",
            "-t",
            "external",
            "-L",
            "2",
            "-d",
            "-x",
            "-s",
            "1",
            "-J",
            "bytes_in,bytes_out",
        ])
        .output()
        .map_err(|_| "process network observation failed".to_string())?;
    if !output.status.success() {
        return Err("process network observation failed".to_string());
    }
    parse_nettop_last_sample(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| "process network observation failed".to_string())
}

fn parse_nettop_last_sample(output: &str) -> Option<BTreeMap<u32, u64>> {
    let mut samples = Vec::new();
    let mut current = BTreeMap::new();
    let mut saw_header = false;
    for line in output.lines() {
        if line.starts_with(",bytes_in,bytes_out") {
            if saw_header {
                samples.push(std::mem::take(&mut current));
            }
            saw_header = true;
            continue;
        }
        if !saw_header {
            continue;
        }
        let mut columns = line.split(',');
        let Some(process) = columns.next() else {
            continue;
        };
        let Some(pid) = process
            .rsplit_once('.')
            .and_then(|(_, pid)| pid.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(bytes_in) = columns.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        let Some(bytes_out) = columns.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        current.insert(pid, bytes_in.saturating_add(bytes_out));
    }
    if saw_header {
        samples.push(current);
    }
    saw_header.then(|| samples.pop().unwrap_or_default())
}

fn aggregate_application_network<'a>(
    applications: &BTreeSet<String>,
    processes: impl Iterator<Item = (&'a Path, u64)>,
) -> Vec<ApplicationNetworkSample> {
    processes
        .filter_map(|(executable, bytes_per_second)| {
            let bundles = application_bundle_names(executable);
            bundles
                .iter()
                .any(|bundle| {
                    applications
                        .iter()
                        .any(|configured| configured.eq_ignore_ascii_case(bundle))
                })
                .then_some(ApplicationNetworkSample {
                    applications: bundles,
                    bytes_per_second,
                })
        })
        .collect()
}

fn application_bundle_names(executable: &Path) -> BTreeSet<String> {
    let components = executable
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>();
    let Some((outer_bundle_index, outer_bundle)) =
        components.iter().enumerate().find_map(|(index, value)| {
            value
                .strip_suffix(".app")
                .filter(|name| !name.is_empty())
                .map(|name| (index, name.to_string()))
        })
    else {
        return BTreeSet::new();
    };

    let mut bundles = BTreeSet::from([outer_bundle.clone()]);
    let relative_components = &components[outer_bundle_index + 1..];
    let bundled_codex_cli = relative_components.len() == 3
        && relative_components[0].eq_ignore_ascii_case("Contents")
        && relative_components[1].eq_ignore_ascii_case("Resources")
        && relative_components[2].eq_ignore_ascii_case("codex");
    let nested_codex_app = relative_components.iter().any(|value| {
        value.strip_suffix(".app").is_some_and(|name| {
            name.eq_ignore_ascii_case("Codex") || name.to_ascii_lowercase().starts_with("codex ")
        })
    });
    let chatgpt_owned_codex_component =
        outer_bundle.eq_ignore_ascii_case("ChatGPT") && (bundled_codex_cli || nested_codex_app);
    if chatgpt_owned_codex_component {
        bundles.insert("Codex".to_string());
    }
    bundles
}

#[cfg(test)]
mod tests {
    use super::{
        aggregate_application_network, application_bundle_names, parse_nettop_last_sample,
        SensorSuite,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    #[test]
    fn owns_main_and_helper_executables_by_outer_app_bundle() {
        assert_eq!(
            application_bundle_names(Path::new("/Applications/Codex.app/Contents/MacOS/Codex")),
            BTreeSet::from(["Codex".to_string()])
        );
        assert_eq!(
            application_bundle_names(Path::new(
                "/Applications/Codex.app/Contents/Frameworks/Codex Helper.app/Contents/MacOS/Codex Helper"
            )),
            BTreeSet::from(["Codex".to_string()])
        );
    }

    #[test]
    fn recognizes_codex_components_owned_by_the_chatgpt_desktop_bundle() {
        assert_eq!(
            application_bundle_names(Path::new(
                "/Applications/ChatGPT.app/Contents/Frameworks/Codex Framework.framework/Versions/A/Helpers/Codex (Service).app/Contents/MacOS/Codex (Service)"
            )),
            BTreeSet::from(["ChatGPT".to_string(), "Codex".to_string()])
        );
        assert_eq!(
            application_bundle_names(Path::new(
                "/Applications/ChatGPT.app/Contents/Resources/codex"
            )),
            BTreeSet::from(["ChatGPT".to_string(), "Codex".to_string()])
        );
    }

    #[test]
    fn rejects_loose_process_name_without_app_bundle() {
        assert_eq!(
            application_bundle_names(Path::new("/opt/homebrew/bin/codex")),
            BTreeSet::new()
        );
        assert_eq!(
            application_bundle_names(Path::new(
                "/Applications/ChatGPT.app/Contents/Helpers/codex"
            )),
            BTreeSet::from(["ChatGPT".to_string()])
        );
    }

    #[test]
    fn sums_main_and_helper_network_for_configured_application_bundle() {
        let configured = BTreeSet::from(["Codex".to_string()]);
        let processes = [
            (
                Path::new("/Applications/Codex.app/Contents/MacOS/Codex"),
                61_500,
            ),
            (
                Path::new(
                    "/Applications/Codex.app/Contents/Frameworks/Codex Helper.app/Contents/MacOS/Codex Helper",
                ),
                42_000,
            ),
            (
                Path::new("/Applications/ChatGPT.app/Contents/Resources/codex"),
                7_500,
            ),
            (Path::new("/opt/homebrew/bin/codex"), 300_000),
        ];
        let samples = aggregate_application_network(&configured, processes.into_iter());
        assert_eq!(
            samples
                .iter()
                .map(|sample| sample.bytes_per_second)
                .sum::<u64>(),
            111_000
        );
    }

    #[test]
    fn counts_a_process_matching_multiple_application_aliases_only_once() {
        let configured = BTreeSet::from(["ChatGPT".to_string(), "Codex".to_string()]);
        let processes = [(
            Path::new("/Applications/ChatGPT.app/Contents/Resources/codex"),
            600,
        )];

        let samples = aggregate_application_network(&configured, processes.into_iter());

        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].bytes_per_second, 600);
        assert_eq!(
            samples[0].applications,
            BTreeSet::from(["ChatGPT".to_string(), "Codex".to_string()])
        );
    }

    #[test]
    fn parses_only_the_last_delta_sample_from_nettop_csv() {
        let output = "\
,bytes_in,bytes_out,
codex.10,1000,2000,
Codex Helper.11,500,700,
,bytes_in,bytes_out,
codex.10,40,60,
Codex Helper.11,10,20,
";
        assert_eq!(
            parse_nettop_last_sample(output),
            Some(BTreeMap::from([(10, 100), (11, 30)]))
        );
    }

    #[test]
    fn rejects_unrecognized_nettop_output_as_an_unknown_observation() {
        assert_eq!(parse_nettop_last_sample("unexpected output"), None);
    }

    #[test]
    fn visibility_cache_is_invalidated_when_the_requested_ssids_change() {
        let old = BTreeSet::from(["old-network".to_string()]);
        let new = BTreeSet::from(["new-network".to_string()]);
        let suite = SensorSuite {
            last_visibility: Some(super::VisibilityCache {
                scanned_at: std::time::Instant::now(),
                requested_ssids: old.clone(),
                visible_ssids: Some(old.clone()),
                error: None,
            }),
            ..SensorSuite::default()
        };

        assert!(!suite.should_scan_visibility(&old));
        assert!(suite.should_scan_visibility(&new));
    }
}
