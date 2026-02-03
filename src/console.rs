use crate::version;

pub fn banner() {
    uefi::println!("{} {}", version::NAME, version::VERSION);
    uefi::println!("amd64 uefi loader (parity track)");
}
