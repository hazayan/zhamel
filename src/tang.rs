extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_void};
use core::ptr;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{AffinePoint, EncodedPoint, ProjectivePoint, PublicKey, SecretKey};
use serde::Deserialize;
use serde_json::Value;
use uefi::boot;
use uefi::boot::{LoadImageSource, ScopedProtocol};
use uefi::proto::device_path::DevicePath;
use uefi::proto::network::http::{Http, HttpBinding};
use uefi::proto::network::ip4config2::Ip4Config2;
use uefi::proto::network::snp::SimpleNetwork;
use uefi::proto::rng::Rng;
use uefi::{CString16, Handle, Status, cstr8};
use uefi_raw::Ipv4Address;
use uefi_raw::protocol::network::http::{
    HttpAccessPoint, HttpConfigData, HttpHeader, HttpMessage, HttpMethod, HttpRequestData,
    HttpResponseData, HttpStatusCode, HttpToken, HttpV4AccessPoint, HttpVersion,
};
use uefi_raw::protocol::network::ip4_config2::{
    Ip4Config2DataType, Ip4Config2ManualAddress, Ip4Config2Policy,
};

use crate::error::{BootError, Result};
use crate::zfs::sha256::Sha256;

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    d: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    key_ops: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug)]
struct TangConfig {
    url: String,
    adv: Option<String>,
}

#[derive(Debug)]
struct JweHeader {
    protected_b64: String,
    kid: String,
    epk: Jwk,
    header: Value,
    tang: TangConfig,
}

pub fn decrypt_tang_jwe(
    jwe: &str,
    url_override: Option<&str>,
    http_driver_path: Option<&str>,
    local_ip: Option<[u8; 4]>,
    local_netmask: Option<[u8; 4]>,
) -> Result<Vec<u8>> {
    let header = parse_jwe_header(jwe, url_override)?;
    if http_driver_path.is_some() {
        try_load_http_driver(http_driver_path);
    }
    let adv = if let Some(adv) = header.tang.adv.as_deref() {
        adv.to_string()
    } else {
        fetch_adv(&header.tang.url, local_ip, local_netmask)?
    };
    let shared_secret = recover_shared_secret(jwe, &adv, &header, local_ip, local_netmask)?;
    let key = derive_key_from_shared_secret(&shared_secret, &header.header)?;
    jwe_decrypt_dir_a256gcm(jwe, &key, &header.protected_b64)
}

fn parse_jwe_header(jwe: &str, url_override: Option<&str>) -> Result<JweHeader> {
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(BootError::InvalidData("jwe compact invalid"));
    }
    let protected_b64 = parts[0].to_string();
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| BootError::InvalidData("jwe header base64"))?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|_| BootError::InvalidData("jwe header"))?;
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(BootError::InvalidData("jwe header kid"))?
        .to_string();
    let epk_value = header
        .get("epk")
        .ok_or(BootError::InvalidData("jwe header epk"))?;
    let epk: Jwk =
        serde_json::from_value(epk_value.clone()).map_err(|_| BootError::InvalidData("jwe epk"))?;
    let clevis = header
        .get("clevis")
        .ok_or(BootError::InvalidData("jwe header clevis"))?;
    let pin = clevis
        .get("pin")
        .and_then(Value::as_str)
        .ok_or(BootError::InvalidData("jwe header clevis pin"))?;
    if pin != "tang" {
        return Err(BootError::InvalidData("clevis pin not tang"));
    }
    let tang = clevis
        .get("tang")
        .ok_or(BootError::InvalidData("clevis tang missing"))?;
    let url = if let Some(url) = url_override {
        url.to_string()
    } else {
        tang.get("url")
            .and_then(Value::as_str)
            .ok_or(BootError::InvalidData("clevis tang url"))?
            .to_string()
    };
    let adv = if let Some(adv) = tang.get("adv") {
        Some(normalize_adv(adv)?)
    } else {
        None
    };
    Ok(JweHeader {
        protected_b64,
        kid,
        epk,
        header,
        tang: TangConfig { url, adv },
    })
}

fn normalize_adv(value: &Value) -> Result<String> {
    if let Some(text) = value.as_str() {
        return Ok(text.to_string());
    }
    serde_json::to_string(value).map_err(|_| BootError::InvalidData("adv serialize"))
}

fn fetch_adv(
    url: &str,
    local_ip: Option<[u8; 4]>,
    local_netmask: Option<[u8; 4]>,
) -> Result<String> {
    let url = format!("{}/adv", url.trim_end_matches('/'));
    let body = http_get(&url, local_ip, local_netmask)?;
    let text = core::str::from_utf8(&body).map_err(|_| BootError::InvalidData("adv utf8"))?;
    Ok(text.to_string())
}

#[derive(Debug)]
struct HttpClient {
    nic_handle: Handle,
    child_handle: Handle,
    binding: ScopedProtocol<HttpBinding>,
    protocol: Option<ScopedProtocol<Http>>,
}

#[derive(Debug)]
struct HttpClientResponse {
    status: HttpStatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpClient {
    fn new(nic_handle: Handle) -> Result<Self> {
        let mut binding = unsafe {
            boot::open_protocol::<HttpBinding>(
                boot::OpenProtocolParams {
                    handle: nic_handle,
                    agent: boot::image_handle(),
                    controller: None,
                },
                boot::OpenProtocolAttributes::GetProtocol,
            )
            .map_err(|err| BootError::Uefi(err.status()))?
        };
        let child_handle = binding
            .create_child()
            .map_err(|err| BootError::Uefi(err.status()))?;
        let protocol = unsafe {
            boot::open_protocol::<Http>(
                boot::OpenProtocolParams {
                    handle: child_handle,
                    agent: boot::image_handle(),
                    controller: None,
                },
                boot::OpenProtocolAttributes::GetProtocol,
            )
            .map_err(|err| BootError::Uefi(err.status()))?
        };
        Ok(Self {
            nic_handle,
            child_handle,
            binding,
            protocol: Some(protocol),
        })
    }

    fn configure_ipv4(
        &mut self,
        local_ip: Option<[u8; 4]>,
        local_netmask: Option<[u8; 4]>,
    ) -> Result<()> {
        let (use_default, local_address, local_subnet) = match local_ip {
            Some(addr) => (
                false,
                Ipv4Address::from(addr),
                Ipv4Address::from(local_netmask.unwrap_or([255, 255, 255, 0])),
            ),
            None => (
                true,
                Ipv4Address::from([0, 0, 0, 0]),
                Ipv4Address::from([0, 0, 0, 0]),
            ),
        };
        if use_default {
            log::info!("tang: http ipv4 config using default addr");
            let mut ip4 =
                Ip4Config2::new(self.nic_handle).map_err(|err| BootError::Uefi(err.status()))?;
            ip4.ifup().map_err(|err| {
                log::warn!("tang: ipv4 dhcp setup failed: {}", err.status());
                BootError::Uefi(err.status())
            })?;
        } else {
            log::info!("tang: http ipv4 config static addr");
            let mut ip4 =
                Ip4Config2::new(self.nic_handle).map_err(|err| BootError::Uefi(err.status()))?;
            ip4.set_policy(Ip4Config2Policy::STATIC)
                .map_err(|err| BootError::Uefi(err.status()))?;
            let mut manual = Ip4Config2ManualAddress {
                address: local_address,
                subnet_mask: local_subnet,
            };
            let data = unsafe {
                core::slice::from_raw_parts_mut(
                    (&mut manual as *mut Ip4Config2ManualAddress).cast::<u8>(),
                    core::mem::size_of::<Ip4Config2ManualAddress>(),
                )
            };
            ip4.set_data(Ip4Config2DataType::MANUAL_ADDRESS, data)
                .map_err(|err| BootError::Uefi(err.status()))?;
        }
        let ip4 = HttpV4AccessPoint {
            use_default_addr: use_default.into(),
            local_address,
            local_subnet,
            local_port: 0,
        };
        let config = HttpConfigData {
            http_version: HttpVersion::HTTP_VERSION_10,
            time_out_millisec: 10_000,
            local_addr_is_ipv6: false.into(),
            access_point: HttpAccessPoint { ipv4_node: &ip4 },
        };
        let protocol = self
            .protocol
            .as_mut()
            .ok_or(BootError::InvalidData("http protocol missing"))?;
        protocol
            .configure(&config)
            .map_err(|err| BootError::Uefi(err.status()))
    }

    fn request(&mut self, method: HttpMethod, url: &str, body: Option<&mut [u8]>) -> Result<()> {
        let url16 = CString16::try_from(url).map_err(|_| BootError::InvalidData("http url"))?;
        let Some(hostname) = url.split('/').nth(2) else {
            return Err(BootError::InvalidData("http host missing"));
        };
        let mut c_hostname = String::from(hostname);
        c_hostname.push('\0');
        let mut tx_req = HttpRequestData {
            method,
            url: url16.as_ptr().cast::<u16>(),
        };
        let mut tx_hdr = Vec::new();
        let mut content_type = None;
        let mut content_length = None;
        if body.is_some() {
            let mut value = String::from("application/json");
            value.push('\0');
            content_type = Some(value);
            let mut length = body
                .as_ref()
                .map(|bytes| bytes.len())
                .unwrap_or(0)
                .to_string();
            length.push('\0');
            content_length = Some(length);
        }
        tx_hdr.push(HttpHeader {
            field_name: cstr8!("Host").as_ptr().cast::<u8>(),
            field_value: c_hostname.as_ptr(),
        });
        if let Some(ref value) = content_type {
            tx_hdr.push(HttpHeader {
                field_name: cstr8!("Content-Type").as_ptr().cast::<u8>(),
                field_value: value.as_ptr(),
            });
        }
        if let Some(ref value) = content_length {
            tx_hdr.push(HttpHeader {
                field_name: cstr8!("Content-Length").as_ptr().cast::<u8>(),
                field_value: value.as_ptr(),
            });
        }
        let mut tx_msg = HttpMessage::default();
        tx_msg.data.request = &mut tx_req;
        tx_msg.header_count = tx_hdr.len();
        tx_msg.header = tx_hdr.as_mut_ptr();
        if let Some(body) = body {
            tx_msg.body_length = body.len();
            tx_msg.body = body.as_mut_ptr().cast::<c_void>();
        }
        let mut tx_token = HttpToken {
            status: Status::NOT_READY,
            message: &mut tx_msg,
            ..Default::default()
        };
        let protocol = self
            .protocol
            .as_mut()
            .ok_or(BootError::InvalidData("http protocol missing"))?;
        protocol
            .request(&mut tx_token)
            .map_err(|err| BootError::Uefi(err.status()))?;
        loop {
            if tx_token.status != Status::NOT_READY {
                break;
            }
            protocol
                .poll()
                .map_err(|err| BootError::Uefi(err.status()))?;
        }
        if tx_token.status != Status::SUCCESS {
            return Err(BootError::Uefi(tx_token.status));
        }
        Ok(())
    }

    fn response_first(&mut self, expect_body: bool) -> Result<HttpClientResponse> {
        let mut rx_rsp = HttpResponseData {
            status_code: HttpStatusCode::STATUS_UNSUPPORTED,
        };
        let mut body = vec![0; if expect_body { 16 * 1024 } else { 0 }];
        let mut rx_msg = HttpMessage::default();
        rx_msg.data.response = &mut rx_rsp;
        rx_msg.body_length = body.len();
        rx_msg.body = if !body.is_empty() {
            body.as_mut_ptr()
        } else {
            ptr::null()
        } as *mut c_void;
        let mut rx_token = HttpToken {
            status: Status::NOT_READY,
            message: &mut rx_msg,
            ..Default::default()
        };
        let protocol = self
            .protocol
            .as_mut()
            .ok_or(BootError::InvalidData("http protocol missing"))?;
        protocol
            .response(&mut rx_token)
            .map_err(|err| BootError::Uefi(err.status()))?;
        loop {
            if rx_token.status != Status::NOT_READY {
                break;
            }
            protocol
                .poll()
                .map_err(|err| BootError::Uefi(err.status()))?;
        }
        if rx_token.status != Status::SUCCESS && rx_token.status != Status::HTTP_ERROR {
            return Err(BootError::Uefi(rx_token.status));
        }
        let mut headers: Vec<(String, String)> = Vec::new();
        for i in 0..rx_msg.header_count {
            let n;
            let v;
            unsafe {
                n = CStr::from_ptr((*rx_msg.header.add(i)).field_name.cast::<c_char>());
                v = CStr::from_ptr((*rx_msg.header.add(i)).field_value.cast::<c_char>());
            }
            headers.push((
                n.to_str().unwrap().to_lowercase(),
                String::from(v.to_str().unwrap()),
            ));
        }
        Ok(HttpClientResponse {
            status: rx_rsp.status_code,
            headers,
            body: body[0..rx_msg.body_length].to_vec(),
        })
    }

    fn response_more(&mut self) -> Result<Vec<u8>> {
        let mut body = vec![0; 16 * 1024];
        let mut rx_msg = HttpMessage {
            body_length: body.len(),
            body: body.as_mut_ptr().cast::<c_void>(),
            ..Default::default()
        };
        let mut rx_token = HttpToken {
            status: Status::NOT_READY,
            message: &mut rx_msg,
            ..Default::default()
        };
        let protocol = self
            .protocol
            .as_mut()
            .ok_or(BootError::InvalidData("http protocol missing"))?;
        protocol
            .response(&mut rx_token)
            .map_err(|err| BootError::Uefi(err.status()))?;
        loop {
            if rx_token.status != Status::NOT_READY {
                break;
            }
            protocol
                .poll()
                .map_err(|err| BootError::Uefi(err.status()))?;
        }
        if rx_token.status != Status::SUCCESS {
            return Err(BootError::Uefi(rx_token.status));
        }
        Ok(body[0..rx_msg.body_length].to_vec())
    }
}

impl Drop for HttpClient {
    fn drop(&mut self) {
        self.protocol = None;
        let _ = self.binding.destroy_child(self.child_handle);
    }
}

fn http_get(
    url: &str,
    local_ip: Option<[u8; 4]>,
    local_netmask: Option<[u8; 4]>,
) -> Result<Vec<u8>> {
    let mut client = open_http_client()?;
    client
        .configure_ipv4(local_ip, local_netmask)
        .map_err(|err| {
            log::warn!("tang: http configure failed: {}", err);
            err
        })?;
    client.request(HttpMethod::GET, url, None).map_err(|err| {
        log::warn!("tang: http get request failed: {}", err);
        err
    })?;
    let rsp = client.response_first(true).map_err(|err| {
        log::warn!("tang: http get response failed: {}", err);
        err
    })?;
    if rsp.status != HttpStatusCode::STATUS_200_OK {
        log::warn!("tang: http get status: {:?}", rsp.status);
    }
    let mut body = rsp.body;
    let expected = content_length(&rsp.headers).unwrap_or(0);
    while expected > 0 && body.len() < expected {
        let more = client.response_more().map_err(|err| {
            log::warn!("tang: http get response more failed: {}", err);
            err
        })?;
        if more.is_empty() {
            break;
        }
        body.extend_from_slice(&more);
    }
    Ok(body)
}

fn http_post(
    url: &str,
    body: &mut [u8],
    local_ip: Option<[u8; 4]>,
    local_netmask: Option<[u8; 4]>,
) -> Result<Vec<u8>> {
    let mut client = open_http_client()?;
    client
        .configure_ipv4(local_ip, local_netmask)
        .map_err(|err| {
            log::warn!("tang: http configure failed: {}", err);
            err
        })?;
    client
        .request(HttpMethod::POST, url, Some(body))
        .map_err(|err| {
            log::warn!("tang: http post request failed: {}", err);
            err
        })?;
    let rsp = client.response_first(true).map_err(|err| {
        log::warn!("tang: http post response failed: {}", err);
        err
    })?;
    if rsp.status != HttpStatusCode::STATUS_200_OK {
        log::warn!("tang: http post status: {:?}", rsp.status);
    }
    let mut data = rsp.body;
    let expected = content_length(&rsp.headers).unwrap_or(0);
    while expected > 0 && data.len() < expected {
        let more = client.response_more().map_err(|err| {
            log::warn!("tang: http post response more failed: {}", err);
            err
        })?;
        if more.is_empty() {
            break;
        }
        data.extend_from_slice(&more);
    }
    Ok(data)
}

fn content_length(headers: &[(String, String)]) -> Option<usize> {
    for (name, value) in headers {
        if name == "content-length" {
            if let Ok(parsed) = value.trim().parse::<usize>() {
                return Some(parsed);
            }
        }
    }
    None
}

fn open_http_client() -> Result<HttpClient> {
    let mut handles = match boot::find_handles::<HttpBinding>() {
        Ok(handles) => handles,
        Err(err) => {
            log::warn!("tang: http binding locate failed: {:?}", err.status());
            Vec::new()
        }
    };
    if !handles.is_empty() {
        log::info!("tang: http binding handles: {}", handles.len());
    }
    match boot::find_handles::<SimpleNetwork>() {
        Ok(nics) => log::info!("tang: simple network handles: {}", nics.len()),
        Err(err) => log::warn!("tang: simple network locate failed: {:?}", err.status()),
    }
    if handles.is_empty() {
        if let Ok(nics) = boot::find_handles::<SimpleNetwork>() {
            for handle in nics {
                let _ = boot::connect_controller(handle, None, None, true);
            }
        }
        handles = match boot::find_handles::<HttpBinding>() {
            Ok(found) => found,
            Err(err) => {
                log::warn!("tang: http binding locate failed: {:?}", err.status());
                Vec::new()
            }
        };
    }
    if handles.is_empty() {
        match boot::find_handles::<DevicePath>() {
            Ok(devices) => {
                log::info!("tang: device path handles: {}", devices.len());
                for handle in devices {
                    let _ = boot::connect_controller(handle, None, None, true);
                }
            }
            Err(err) => log::warn!("tang: device path locate failed: {:?}", err.status()),
        }
        handles = match boot::find_handles::<HttpBinding>() {
            Ok(found) => found,
            Err(err) => {
                log::warn!("tang: http binding locate failed: {:?}", err.status());
                Vec::new()
            }
        };
    }
    match boot::find_handles::<SimpleNetwork>() {
        Ok(nics) => log::info!("tang: simple network handles after connect: {}", nics.len()),
        Err(err) => log::warn!(
            "tang: simple network locate after connect failed: {:?}",
            err.status()
        ),
    }
    let handle = handles.first().copied().ok_or_else(|| {
        log::warn!("tang: http binding missing after connect");
        BootError::InvalidData("http binding missing")
    })?;
    HttpClient::new(handle)
}

fn try_load_http_driver(path: Option<&str>) {
    if load_cached_http_drivers() {
        return;
    }
    let Some(path) = path else {
        return;
    };
    let mut bytes = crate::fs::uefi::read_file_from_any_fs(path);
    if bytes.is_none() {
        if let Some((dir, file)) = split_uefi_path(path) {
            if let Some(entries) = crate::fs::uefi::read_dir_entries_from_any_fs(&dir) {
                for entry in entries {
                    if entry.eq_ignore_ascii_case(&file) {
                        let candidate = format!("{}\\{}", dir.trim_end_matches('\\'), entry);
                        bytes = crate::fs::uefi::read_file_from_any_fs(&candidate);
                        break;
                    }
                }
            }
        }
    }
    if bytes.is_none() {
        bytes = crate::fs::uefi::read_file_from_boot_volume(path);
    }
    let Some(bytes) = bytes else {
        if let Some(entries) = crate::fs::uefi::read_dir_entries_from_any_fs("\\EFI\\FreeBSD") {
            log::warn!("tang: EFI/FreeBSD entries: {:?}", entries);
        }
        log::warn!("tang: http driver not found at {}", path);
        return;
    };
    load_http_driver_from_bytes(&bytes);
}

pub fn cache_http_drivers(paths: &str) {
    if !get_cached_http_drivers().is_empty() {
        return;
    }
    for path in paths
        .split(',')
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        if let Some(bytes) = crate::fs::uefi::read_file_from_boot_volume(path) {
            push_cached_http_driver(bytes);
            log::info!("tang: cached http driver from {}", path);
        } else {
            log::warn!("tang: failed to cache http driver from {}", path);
        }
    }
}

fn get_cached_http_drivers() -> Vec<Vec<u8>> {
    unsafe { (*HTTP_DRIVER_BYTES.0.get()).clone() }
}

fn push_cached_http_driver(bytes: Vec<u8>) {
    unsafe {
        (*HTTP_DRIVER_BYTES.0.get()).push(bytes);
    }
}

fn load_cached_http_drivers() -> bool {
    let drivers = get_cached_http_drivers();
    if drivers.is_empty() {
        return false;
    }
    for bytes in drivers {
        load_http_driver_from_bytes(&bytes);
    }
    true
}

fn load_http_driver_from_bytes(bytes: &[u8]) {
    let source = LoadImageSource::FromBuffer {
        buffer: bytes,
        file_path: None,
    };
    let image = match boot::load_image(boot::image_handle(), source) {
        Ok(image) => image,
        Err(err) => {
            log::warn!("tang: http driver load failed: {:?}", err.status());
            return;
        }
    };
    if let Err(err) = boot::start_image(image) {
        log::warn!("tang: http driver start failed: {:?}", err.status());
    } else {
        log::info!("tang: http driver started");
    }
}

struct HttpDriverCache(UnsafeCell<Vec<Vec<u8>>>);

unsafe impl Sync for HttpDriverCache {}

static HTTP_DRIVER_BYTES: HttpDriverCache = HttpDriverCache(UnsafeCell::new(Vec::new()));

fn split_uefi_path(path: &str) -> Option<(String, String)> {
    let mut normalized = path.replace('/', "\\");
    if !normalized.starts_with('\\') {
        normalized.insert(0, '\\');
    }
    let idx = normalized.rfind('\\')?;
    let file = normalized[idx + 1..].to_string();
    let dir = if idx == 0 {
        "\\".to_string()
    } else {
        normalized[..idx].to_string()
    };
    Some((dir, file))
}

fn recover_shared_secret(
    _jwe: &str,
    adv: &str,
    header: &JweHeader,
    local_ip: Option<[u8; 4]>,
    local_netmask: Option<[u8; 4]>,
) -> Result<Vec<u8>> {
    let jwk_set = parse_adv_jwk_set(adv)?;
    let server_key = find_exchange_key(&jwk_set, &header.kid)?;
    let client_pub = public_key_from_jwk(&header.epk)?;
    let eph_secret = generate_secret_key()?;
    let eph_pub = eph_secret.public_key();
    let x_point = ProjectivePoint::from(client_pub) + ProjectivePoint::from(eph_pub);
    let x_jwk = jwk_from_point(&x_point)?;
    let mut request =
        serde_json::to_vec(&x_jwk).map_err(|_| BootError::InvalidData("recover request"))?;
    let rec_url = format!(
        "{}/rec/{}",
        header.tang.url.trim_end_matches('/'),
        header.kid
    );
    let response = http_post(&rec_url, &mut request, local_ip, local_netmask)?;
    let response_jwk: Jwk = serde_json::from_slice(&response).map_err(|_| {
        if let Ok(text) = core::str::from_utf8(&response) {
            log::warn!("tang: recover response text: {}", text);
        } else {
            log::warn!("tang: recover response bytes len={}", response.len());
        }
        BootError::InvalidData("recover response")
    })?;
    let server_pub = public_key_from_jwk(&server_key)?;
    let response_pub = public_key_from_jwk(&response_jwk)?;
    let z = ProjectivePoint::from(server_pub) * p256::Scalar::from(&eph_secret);
    let y = ProjectivePoint::from(response_pub);
    let k = y - z;
    let affine = AffinePoint::from(k);
    let encoded = EncodedPoint::from(affine);
    let x_bytes = encoded
        .x()
        .ok_or(BootError::InvalidData("shared secret x"))?;
    Ok(x_bytes.as_slice().to_vec())
}

fn parse_adv_jwk_set(adv: &str) -> Result<JwkSet> {
    let trimmed = adv.trim();
    if trimmed.starts_with('{') {
        let value: Value =
            serde_json::from_str(trimmed).map_err(|_| BootError::InvalidData("adv json"))?;
        let payload_b64 = value
            .get("payload")
            .and_then(Value::as_str)
            .ok_or(BootError::InvalidData("adv payload missing"))?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| BootError::InvalidData("adv payload base64"))?;
        return serde_json::from_slice(&payload)
            .map_err(|_| BootError::InvalidData("adv payload json"));
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() != 3 {
        return Err(BootError::InvalidData("adv jws invalid"));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| BootError::InvalidData("adv payload base64"))?;
    serde_json::from_slice(&payload).map_err(|_| BootError::InvalidData("adv payload json"))
}

fn find_exchange_key(set: &JwkSet, kid: &str) -> Result<Jwk> {
    for key in &set.keys {
        if key.kty != "EC" {
            continue;
        }
        if key.alg.as_deref() != Some("ECMR") {
            continue;
        }
        if !key_ops_contains(key, "deriveKey") {
            continue;
        }
        let thp = thumbprint_ec(key)?;
        if thp == kid {
            return Ok(key.clone());
        }
    }
    Err(BootError::InvalidData("no exchange key for kid"))
}

fn key_ops_contains(key: &Jwk, op: &str) -> bool {
    key.key_ops
        .as_ref()
        .map(|ops| ops.iter().any(|value| value == op))
        .unwrap_or(false)
}

fn thumbprint_ec(key: &Jwk) -> Result<String> {
    let crv = key
        .crv
        .as_deref()
        .ok_or(BootError::InvalidData("jwk crv missing"))?;
    let x = key
        .x
        .as_deref()
        .ok_or(BootError::InvalidData("jwk x missing"))?;
    let y = key
        .y
        .as_deref()
        .ok_or(BootError::InvalidData("jwk y missing"))?;
    let canonical = format!(
        "{{\"crv\":\"{}\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        crv, x, y
    );
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

fn public_key_from_jwk(key: &Jwk) -> Result<PublicKey> {
    let crv = key
        .crv
        .as_deref()
        .ok_or(BootError::InvalidData("jwk crv missing"))?;
    if crv != "P-256" {
        return Err(BootError::InvalidData("jwk crv unsupported"));
    }
    let x = key
        .x
        .as_deref()
        .ok_or(BootError::InvalidData("jwk x missing"))?;
    let y = key
        .y
        .as_deref()
        .ok_or(BootError::InvalidData("jwk y missing"))?;
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| BootError::InvalidData("jwk x base64"))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| BootError::InvalidData("jwk y base64"))?;
    let x_arr: [u8; 32] = x_bytes
        .try_into()
        .map_err(|_| BootError::InvalidData("jwk x size"))?;
    let y_arr: [u8; 32] = y_bytes
        .try_into()
        .map_err(|_| BootError::InvalidData("jwk y size"))?;
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x_arr);
    point.extend_from_slice(&y_arr);
    let encoded =
        EncodedPoint::from_bytes(&point).map_err(|_| BootError::InvalidData("jwk point"))?;
    PublicKey::from_sec1_bytes(encoded.as_bytes())
        .map_err(|_| BootError::InvalidData("jwk public key"))
}

fn jwk_from_point(point: &ProjectivePoint) -> Result<Jwk> {
    let affine = AffinePoint::from(*point);
    let encoded = EncodedPoint::from(affine);
    let x = encoded.x().ok_or(BootError::InvalidData("jwk x"))?;
    let y = encoded.y().ok_or(BootError::InvalidData("jwk y"))?;
    let x = URL_SAFE_NO_PAD.encode(x);
    let y = URL_SAFE_NO_PAD.encode(y);
    Ok(Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: Some(x),
        y: Some(y),
        d: None,
        alg: Some("ECMR".to_string()),
        key_ops: Some(vec!["deriveKey".to_string()]),
    })
}

fn generate_secret_key() -> Result<SecretKey> {
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        rng_fill(&mut bytes)?;
        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            return Ok(secret);
        }
    }
    Err(BootError::InvalidData("ephemeral key generation failed"))
}

fn rng_fill(buf: &mut [u8]) -> Result<()> {
    let handles = boot::find_handles::<Rng>().map_err(|err| BootError::Uefi(err.status()))?;
    let handle = handles
        .first()
        .copied()
        .ok_or(BootError::InvalidData("rng handle missing"))?;
    let mut rng = boot::open_protocol_exclusive::<Rng>(handle)
        .map_err(|err| BootError::Uefi(err.status()))?;
    rng.get_rng(None, buf)
        .map_err(|err| BootError::Uefi(err.status()))
}

fn jwe_decrypt_dir_a256gcm(jwe: &str, key: &[u8], protected_b64: &str) -> Result<Vec<u8>> {
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(BootError::InvalidData("jwe compact invalid"));
    }
    let iv = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| BootError::InvalidData("jwe iv"))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|_| BootError::InvalidData("jwe ciphertext"))?;
    let tag = URL_SAFE_NO_PAD
        .decode(parts[4])
        .map_err(|_| BootError::InvalidData("jwe tag"))?;
    if iv.len() != 12 {
        return Err(BootError::InvalidData("jwe iv size"));
    }
    aes_gcm_decrypt(key, &iv, protected_b64.as_bytes(), &ciphertext, &tag)
}

fn derive_key_from_shared_secret(shared_secret: &[u8], header: &Value) -> Result<Vec<u8>> {
    let enc = header
        .get("enc")
        .and_then(Value::as_str)
        .unwrap_or("A256GCM");
    let key_size = match enc {
        "A256GCM" => 32,
        _ => return Err(BootError::InvalidData("jwe enc unsupported")),
    };
    let mut other = Vec::new();
    other.extend_from_slice(&(enc.len() as u32).to_be_bytes());
    other.extend_from_slice(enc.as_bytes());
    if let Some(apu) = header.get("apu").and_then(Value::as_str) {
        let apu_bytes = URL_SAFE_NO_PAD
            .decode(apu)
            .map_err(|_| BootError::InvalidData("jwe apu"))?;
        other.extend_from_slice(&(apu_bytes.len() as u32).to_be_bytes());
        other.extend_from_slice(&apu_bytes);
    } else {
        other.extend_from_slice(&0u32.to_be_bytes());
    }
    if let Some(apv) = header.get("apv").and_then(Value::as_str) {
        let apv_bytes = URL_SAFE_NO_PAD
            .decode(apv)
            .map_err(|_| BootError::InvalidData("jwe apv"))?;
        other.extend_from_slice(&(apv_bytes.len() as u32).to_be_bytes());
        other.extend_from_slice(&apv_bytes);
    } else {
        other.extend_from_slice(&0u32.to_be_bytes());
    }
    other.extend_from_slice(&((key_size * 8) as u32).to_be_bytes());
    Ok(concat_kdf(shared_secret, &other, key_size))
}

fn concat_kdf(shared_secret: &[u8], other_info: &[u8], keydatalen: usize) -> Vec<u8> {
    let hash_len = 32;
    let n = (keydatalen + hash_len - 1) / hash_len;
    let mut out = Vec::with_capacity(n * hash_len);
    for idx in 1..=n {
        let mut hasher = Sha256::new();
        hasher.update(&(idx as u32).to_be_bytes());
        hasher.update(shared_secret);
        hasher.update(other_info);
        out.extend_from_slice(&hasher.finalize());
    }
    out.truncate(keydatalen);
    out
}

fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(BootError::InvalidData("aes key size"));
    }
    if iv.len() != 12 {
        return Err(BootError::InvalidData("aes iv size"));
    }
    let cipher = Aes256Key::new(key)?;
    let h = ghash_key(&cipher);
    let j0 = j0_from_iv(&h, iv);
    let s = ghash(&h, aad, ciphertext);
    let tag_calc = xor_block(&aes_block(&cipher, &j0), &s);
    if tag_calc != to_block(tag) {
        return Err(BootError::InvalidData("aes tag mismatch"));
    }
    Ok(aes_ctr_decrypt(&cipher, &j0, ciphertext))
}

fn aes_block(cipher: &Aes256Key, block: &[u8; 16]) -> [u8; 16] {
    cipher.encrypt_block(block)
}

fn ghash_key(cipher: &Aes256Key) -> [u8; 16] {
    cipher.encrypt_block(&[0u8; 16])
}

fn j0_from_iv(h: &[u8; 16], iv: &[u8]) -> [u8; 16] {
    let mut j0 = [0u8; 16];
    if iv.len() == 12 {
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        return j0;
    }
    let s = ghash(h, &[], iv);
    s
}

fn aes_ctr_decrypt(cipher: &Aes256Key, j0: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut counter = inc32(*j0);
    for chunk in ciphertext.chunks(16) {
        let keystream = aes_block(cipher, &counter);
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for (idx, byte) in block[..chunk.len()].iter().enumerate() {
            out.push(byte ^ keystream[idx]);
        }
        counter = inc32(counter);
    }
    out
}

fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = 0u128;
    let h = u128::from_be_bytes(*h);
    for block in blocks(aad) {
        y = gf_mul(y ^ block, h);
    }
    for block in blocks(ciphertext) {
        y = gf_mul(y ^ block, h);
    }
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());
    let len_val = u128::from_be_bytes(len_block);
    y = gf_mul(y ^ len_val, h);
    y.to_be_bytes()
}

fn blocks(data: &[u8]) -> impl Iterator<Item = u128> + '_ {
    data.chunks(16).map(|chunk| {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        u128::from_be_bytes(block)
    })
}

fn gf_mul(mut x: u128, mut y: u128) -> u128 {
    let r: u128 = 0xe1000000000000000000000000000000;
    let mut z = 0u128;
    for _ in 0..128 {
        if (x & (1u128 << 127)) != 0 {
            z ^= y;
        }
        let lsb = y & 1;
        y >>= 1;
        if lsb != 0 {
            y ^= r;
        }
        x <<= 1;
    }
    z
}

fn inc32(mut counter: [u8; 16]) -> [u8; 16] {
    let mut n = u32::from_be_bytes(counter[12..16].try_into().unwrap());
    n = n.wrapping_add(1);
    counter[12..16].copy_from_slice(&n.to_be_bytes());
    counter
}

fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for idx in 0..16 {
        out[idx] = a[idx] ^ b[idx];
    }
    out
}

fn to_block(data: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let len = core::cmp::min(data.len(), 16);
    out[..len].copy_from_slice(&data[..len]);
    out
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::format;
    use alloc::string::{String, ToString};

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::{Value, json};

    use super::{parse_adv_jwk_set, parse_jwe_header};

    fn compact_jwe_with_header(header: Value) -> String {
        let header = serde_json::to_vec(&header).expect("header json");
        format!("{}....", URL_SAFE_NO_PAD.encode(header))
    }

    #[test]
    fn parse_jwe_header_accepts_kunci_tang_shape() {
        let adv = json!({
            "payload": URL_SAFE_NO_PAD.encode(br#"{"keys":[]}"#),
            "signatures": []
        });
        let jwe = compact_jwe_with_header(json!({
            "alg": "ECDH-ES",
            "enc": "A256GCM",
            "kid": "exchange-thumbprint",
            "epk": {
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
                "y": URL_SAFE_NO_PAD.encode([2u8; 32]),
                "alg": "ECMR",
                "key_ops": ["deriveKey"]
            },
            "clevis": {
                "pin": "tang",
                "tang": {
                    "url": "http://tang.example",
                    "adv": adv
                }
            }
        }));

        let header = parse_jwe_header(&jwe, None).expect("parse header");
        assert_eq!(header.kid, "exchange-thumbprint");
        assert_eq!(header.tang.url, "http://tang.example");
        assert!(header.tang.adv.expect("adv").contains("\"payload\""));
    }

    #[test]
    fn parse_jwe_header_allows_url_override() {
        let jwe = compact_jwe_with_header(json!({
            "kid": "exchange-thumbprint",
            "epk": {
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
                "y": URL_SAFE_NO_PAD.encode([2u8; 32])
            },
            "clevis": {
                "pin": "tang",
                "tang": {
                    "url": "http://configured.example"
                }
            }
        }));

        let header = parse_jwe_header(&jwe, Some("http://override.example")).expect("parse header");
        assert_eq!(header.tang.url, "http://override.example");
    }

    #[test]
    fn parse_adv_accepts_kunci_json_advertisement() {
        let adv = json!({
            "payload": URL_SAFE_NO_PAD.encode(br#"{"keys":[]}"#),
            "signatures": []
        })
        .to_string();

        let set = parse_adv_jwk_set(&adv).expect("parse adv");
        assert!(set.keys.is_empty());
    }

    #[test]
    fn parse_jwe_header_rejects_non_tang_pin() {
        let jwe = compact_jwe_with_header(json!({
            "kid": "exchange-thumbprint",
            "epk": {
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
                "y": URL_SAFE_NO_PAD.encode([2u8; 32])
            },
            "clevis": {
                "pin": "sss",
                "tang": {
                    "url": "http://tang.example"
                }
            }
        }));

        assert!(parse_jwe_header(&jwe, None).is_err());
    }
}

struct Aes256Key {
    round_keys: [u32; 60],
}

impl Aes256Key {
    fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(BootError::InvalidData("aes key size"));
        }
        let mut key_words = [0u32; 8];
        for i in 0..8 {
            let offset = i * 4;
            key_words[i] = u32::from_be_bytes([
                key[offset],
                key[offset + 1],
                key[offset + 2],
                key[offset + 3],
            ]);
        }
        let mut round_keys = [0u32; 60];
        round_keys[..8].copy_from_slice(&key_words);
        for i in 8..60 {
            let mut temp = round_keys[i - 1];
            if i % 8 == 0 {
                temp = sub_word(rot_word(temp)) ^ (RCON[(i / 8) - 1] << 24);
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }
            round_keys[i] = round_keys[i - 8] ^ temp;
        }
        Ok(Self { round_keys })
    }

    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;
        add_round_key(&mut state, &self.round_keys[0..4]);
        for round in 1..14 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.round_keys[round * 4..(round + 1) * 4]);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.round_keys[56..60]);
        state
    }
}

fn add_round_key(state: &mut [u8; 16], round_key: &[u32]) {
    for (col, word) in round_key.iter().enumerate() {
        let bytes = word.to_be_bytes();
        let idx = col * 4;
        state[idx] ^= bytes[0];
        state[idx + 1] ^= bytes[1];
        state[idx + 2] ^= bytes[2];
        state[idx + 3] ^= bytes[3];
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let mut tmp = [0u8; 16];
    tmp[0] = state[0];
    tmp[4] = state[4];
    tmp[8] = state[8];
    tmp[12] = state[12];
    tmp[1] = state[5];
    tmp[5] = state[9];
    tmp[9] = state[13];
    tmp[13] = state[1];
    tmp[2] = state[10];
    tmp[6] = state[14];
    tmp[10] = state[2];
    tmp[14] = state[6];
    tmp[3] = state[15];
    tmp[7] = state[3];
    tmp[11] = state[7];
    tmp[15] = state[11];
    *state = tmp;
}

fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let idx = col * 4;
        let a0 = state[idx];
        let a1 = state[idx + 1];
        let a2 = state[idx + 2];
        let a3 = state[idx + 3];
        state[idx] = mul2(a0) ^ mul3(a1) ^ a2 ^ a3;
        state[idx + 1] = a0 ^ mul2(a1) ^ mul3(a2) ^ a3;
        state[idx + 2] = a0 ^ a1 ^ mul2(a2) ^ mul3(a3);
        state[idx + 3] = mul3(a0) ^ a1 ^ a2 ^ mul2(a3);
    }
}

fn sub_word(word: u32) -> u32 {
    let bytes = word.to_be_bytes();
    u32::from_be_bytes([
        SBOX[bytes[0] as usize],
        SBOX[bytes[1] as usize],
        SBOX[bytes[2] as usize],
        SBOX[bytes[3] as usize],
    ])
}

fn rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

fn mul2(value: u8) -> u8 {
    let x = value << 1;
    if value & 0x80 != 0 { x ^ 0x1b } else { x }
}

fn mul3(value: u8) -> u8 {
    mul2(value) ^ value
}

const RCON: [u32; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];
