use uefi::runtime;

pub fn init() {
    match runtime::get_time() {
        Ok(time) => {
            log::info!(
                "time: {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                time.year(),
                time.month(),
                time.day(),
                time.hour(),
                time.minute(),
                time.second()
            );
        }
        Err(err) => {
            log::warn!("time: read failed: {:?}", err.status());
        }
    }
}
