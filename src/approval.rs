//! Native macOS approval prompts for granting browser access.

//! The web control center listens on loopback and is reachable from any browser
//! on this Mac. A new browser profile must be authorized by the logged-in user
//! through a native Allow/Deny prompt, so a webpage can never approve its own
//! access.

use std::time::Duration;

use anyhow::{Context, Result};

/// A user decision for one pending browser authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// The user explicitly allowed this browser.
    Allowed,
    /// The user explicitly denied this browser.
    Denied,
    /// The prompt could not be presented to the user.
    Unavailable,
}

impl ApprovalDecision {
    /// Machine-readable name recorded in logs and returned to the browser.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Presents a native approval prompt and returns the user's decision.
///
/// The blocking interaction with the GUI session runs on a blocking thread so
/// the caller's event loops are never stalled. A denial and a timeout are
/// reported distinctly from a failure to present the prompt at all.
pub async fn request_approval(title: &str, message: &str, timeout: Duration) -> Result<ApprovalDecision> {
    let title = title.to_string();
    let message = message.to_string();
    #[cfg(target_os = "macos")]
    {
        tokio::task::spawn_blocking(move || macos_prompt(&title, &message, timeout))
            .await
            .context("join the native approval prompt")
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (title, message, timeout);
        Ok(ApprovalDecision::Unavailable)
    }
}

#[cfg(target_os = "macos")]
fn macos_prompt(title: &str, message: &str, timeout: Duration) -> ApprovalDecision {
    use core_foundation::base::{kCFAllocatorDefault, TCFType};
    use core_foundation::dictionary::CFDictionary;
use core_foundation_sys::dictionary::CFDictionaryRef;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::{CFOptionFlags, SInt32};
    use core_foundation_sys::date::CFTimeInterval;
    use core_foundation_sys::user_notification::{
        kCFUserNotificationAlertHeaderKey, kCFUserNotificationAlertMessageKey,
        kCFUserNotificationAlternateButtonTitleKey, kCFUserNotificationAlternateResponse,
        kCFUserNotificationCautionAlertLevel, kCFUserNotificationDefaultButtonTitleKey,
        kCFUserNotificationDefaultResponse, CFUserNotificationCancel, CFUserNotificationCreate,
        CFUserNotificationReceiveResponse,
    };

    let header = CFString::new(title);
    let body = CFString::new(message);
    let allow = CFString::new("Allow");
    let deny = CFString::new("Deny");

    let dictionary = unsafe {
        CFDictionary::from_CFType_pairs(&[
            (CFString::wrap_under_get_rule(kCFUserNotificationAlertHeaderKey), header),
            (CFString::wrap_under_get_rule(kCFUserNotificationAlertMessageKey), body),
            (CFString::wrap_under_get_rule(kCFUserNotificationDefaultButtonTitleKey), allow),
            (
                CFString::wrap_under_get_rule(kCFUserNotificationAlternateButtonTitleKey),
                deny,
            ),
        ])
    };

    let timeout_seconds: CFTimeInterval = timeout.as_secs_f64();
    let mut error: SInt32 = 0;
    let notification = unsafe {
        CFUserNotificationCreate(
            kCFAllocatorDefault,
            timeout_seconds,
            kCFUserNotificationCautionAlertLevel,
            &mut error,
            dictionary.as_concrete_TypeRef() as CFDictionaryRef,
        )
    };
    if notification.is_null() {
        return ApprovalDecision::Unavailable;
    }

    let mut response_flags: CFOptionFlags = 0;
    let status =
        unsafe { CFUserNotificationReceiveResponse(notification, timeout_seconds, &mut response_flags) };
    unsafe { CFUserNotificationCancel(notification) };

    if status != 0 {
        return ApprovalDecision::Unavailable;
    }
    let response = response_flags & 0b11;
    if response == kCFUserNotificationDefaultResponse {
        ApprovalDecision::Allowed
    } else if response == kCFUserNotificationAlternateResponse {
        ApprovalDecision::Denied
    } else {
        ApprovalDecision::Denied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_names_are_stable() {
        assert_eq!(ApprovalDecision::Allowed.as_str(), "allowed");
        assert_eq!(ApprovalDecision::Denied.as_str(), "denied");
        assert_eq!(ApprovalDecision::Unavailable.as_str(), "unavailable");
    }
}
