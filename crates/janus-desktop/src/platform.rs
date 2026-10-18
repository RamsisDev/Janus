//! What the client needs from the desktop OS: the storage key, a clock that counts during sleep,
//! and a data directory.

use std::fs;

use zeroize::Zeroizing;

const SERVICE: &str = "org.janusknot.janus";
const ACCOUNT: &str = "storage-key";

pub struct DesktopPlatform {
    key: Zeroizing<Vec<u8>>,
    dir: String,
}

impl DesktopPlatform {
    pub fn new() -> Result<DesktopPlatform, String> {
        let dirs = directories::ProjectDirs::from("org", "janusknot", "Janus")
            .ok_or("no home directory")?;
        let dir = dirs.data_local_dir();
        fs::create_dir_all(dir).map_err(|e| format!("data directory: {e}"))?;
        Ok(DesktopPlatform {
            key: storage_key()?,
            dir: dir.to_string_lossy().into_owned(),
        })
    }
}

impl janus_ffi::Platform for DesktopPlatform {
    fn storage_key(&self) -> Vec<u8> {
        self.key.to_vec()
    }

    fn now_ms(&self) -> u64 {
        boot_ms()
    }

    fn data_dir(&self) -> String {
        self.dir.clone()
    }
}

/// 32 random bytes made on first launch and kept by the OS keychain: the Credential Manager on
/// Windows, the Secret Service (GNOME Keyring, KWallet) on Linux. Without one the app does not
/// start, rather than leave the key in a plain file.
fn storage_key() -> Result<Zeroizing<Vec<u8>>, String> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT).map_err(no_keychain)?;
    match entry.get_secret() {
        Ok(key) => Ok(Zeroizing::new(key)),
        Err(keyring::Error::NoEntry) => {
            let mut key = Zeroizing::new(vec![0; 32]);
            getrandom::fill(&mut key).map_err(|e| e.to_string())?;
            entry.set_secret(&key).map_err(no_keychain)?;
            Ok(key)
        }
        Err(e) => Err(no_keychain(e)),
    }
}

fn no_keychain(e: keyring::Error) -> String {
    format!(
        "The system keychain is not available ({e}). On Linux, run a Secret Service such as \
         GNOME Keyring or KWallet."
    )
}

/// Milliseconds since boot, counting while the computer sleeps.
#[cfg(unix)]
fn boot_ms() -> u64 {
    use rustix::time::{ClockId, clock_gettime};
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let clock = ClockId::Boottime;
    // Darwin's CLOCK_MONOTONIC keeps counting during sleep; elsewhere it may not.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let clock = ClockId::Monotonic;
    let t = clock_gettime(clock);
    t.tv_sec as u64 * 1000 + t.tv_nsec as u64 / 1_000_000
}

/// Milliseconds since boot (`GetTickCount64`), counting while the computer sleeps.
#[cfg(windows)]
fn boot_ms() -> u64 {
    uptime_lib::get().map_or(0, |d| d.as_millis() as u64)
}
