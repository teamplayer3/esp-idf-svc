use core::cell::UnsafeCell;
use core::cmp;
use core::future::Future;
use core::ptr;
use core::time::Duration;

extern crate alloc;
use alloc::sync::Arc;

use ::log::*;

use enumset::*;

use embedded_svc::event_bus::{ErrorType, EventBus};
use embedded_svc::ipv4;
use embedded_svc::wifi::*;

use esp_idf_hal::mutex;

use esp_idf_sys::*;

use crate::eventloop::{EspSubscription, EspTypedEventDeserializer, EspTypedEventSource, System};
use crate::netif::*;
use crate::nvs::EspDefaultNvs;
use crate::private::common::*;
use crate::private::cstr::*;
use crate::private::waitable::*;
use crate::private::waker_registry::WakerRegistry;
use crate::sysloop::*;

#[cfg(feature = "experimental")]
use asyncify::*;

/// more info: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/wifi.html?highlight=wifi%20scan#esp32-wi-fi-scan
#[derive(Debug)]
#[repr(u32)]
pub enum ScanType {
    Active = 0,
    Passive = 1,
}

impl From<ScanType> for u32 {
    fn from(s: ScanType) -> Self {
        match s {
            ScanType::Active => 0,
            ScanType::Passive => 1,
        }
    }
}

impl Default for ScanType {
    fn default() -> Self {
        Self::Active
    }
}

/// more info: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/wifi.html?highlight=wifi%20scan#esp32-wi-fi-scan
#[derive(Debug)]
pub struct ScanTime {
    pub active: (u32, u32),
    pub passive: u32,
}

impl Default for ScanTime {
    fn default() -> Self {
        Self {
            active: (0, 0),
            passive: 0,
        }
    }
}

#[derive(Default, Debug)]
pub struct ScanConfig {
    pub bssid: Option<[u8; 8]>,
    pub ssid: Option<String>,
    pub channel: Option<u8>,
    pub scan_type: ScanType,
    pub scan_time: ScanTime,
    pub show_hidden: bool,
}

impl From<ScanConfig> for wifi_scan_config_t {
    fn from(s: ScanConfig) -> Self {
        Self {
            bssid: s.bssid.map_or(ptr::null(), |v| v.as_ptr()) as *mut u8,
            ssid: s.ssid.map_or(ptr::null(), |v| v.as_ptr()) as *mut u8,
            scan_time: wifi_scan_time_t {
                active: wifi_active_scan_time_t {
                    min: s.scan_time.active.0,
                    max: s.scan_time.active.1,
                },
                passive: s.scan_time.passive,
            },
            channel: s.channel.unwrap_or_default(),
            scan_type: s.scan_type.into(),
            show_hidden: s.show_hidden,
        }
    }
}

impl From<AuthMethod> for Newtype<wifi_auth_mode_t> {
    fn from(method: AuthMethod) -> Self {
        Newtype(match method {
            AuthMethod::None => wifi_auth_mode_t_WIFI_AUTH_OPEN,
            AuthMethod::WEP => wifi_auth_mode_t_WIFI_AUTH_WEP,
            AuthMethod::WPA => wifi_auth_mode_t_WIFI_AUTH_WPA_PSK,
            AuthMethod::WPA2Personal => wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK,
            AuthMethod::WPAWPA2Personal => wifi_auth_mode_t_WIFI_AUTH_WPA_WPA2_PSK,
            AuthMethod::WPA2Enterprise => wifi_auth_mode_t_WIFI_AUTH_WPA2_ENTERPRISE,
            AuthMethod::WPA3Personal => wifi_auth_mode_t_WIFI_AUTH_WPA3_PSK,
            AuthMethod::WPA2WPA3Personal => wifi_auth_mode_t_WIFI_AUTH_WPA2_WPA3_PSK,
            AuthMethod::WAPIPersonal => wifi_auth_mode_t_WIFI_AUTH_WAPI_PSK,
        })
    }
}

impl From<Newtype<wifi_auth_mode_t>> for AuthMethod {
    #[allow(non_upper_case_globals)]
    fn from(mode: Newtype<wifi_auth_mode_t>) -> Self {
        match mode.0 {
            wifi_auth_mode_t_WIFI_AUTH_OPEN => AuthMethod::None,
            wifi_auth_mode_t_WIFI_AUTH_WEP => AuthMethod::WEP,
            wifi_auth_mode_t_WIFI_AUTH_WPA_PSK => AuthMethod::WPA,
            wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK => AuthMethod::WPA2Personal,
            wifi_auth_mode_t_WIFI_AUTH_WPA_WPA2_PSK => AuthMethod::WPAWPA2Personal,
            wifi_auth_mode_t_WIFI_AUTH_WPA2_ENTERPRISE => AuthMethod::WPA2Enterprise,
            wifi_auth_mode_t_WIFI_AUTH_WPA3_PSK => AuthMethod::WPA3Personal,
            wifi_auth_mode_t_WIFI_AUTH_WPA2_WPA3_PSK => AuthMethod::WPA2WPA3Personal,
            wifi_auth_mode_t_WIFI_AUTH_WAPI_PSK => AuthMethod::WAPIPersonal,
            _ => panic!(),
        }
    }
}

impl From<&ClientConfiguration> for Newtype<wifi_sta_config_t> {
    fn from(conf: &ClientConfiguration) -> Self {
        let bssid: [u8; 6] = match &conf.bssid {
            Some(bssid_ref) => *bssid_ref,
            None => [0; 6],
        };

        let mut result = wifi_sta_config_t {
            ssid: [0; 32],
            password: [0; 64],
            scan_method: wifi_scan_method_t_WIFI_FAST_SCAN,
            bssid_set: conf.bssid.is_some(),
            bssid,
            channel: conf.channel.unwrap_or(0u8),
            listen_interval: 0,
            sort_method: wifi_sort_method_t_WIFI_CONNECT_AP_BY_SIGNAL,
            threshold: wifi_scan_threshold_t {
                rssi: 127,
                authmode: Newtype::<wifi_auth_mode_t>::from(conf.auth_method).0,
            },
            pmf_cfg: wifi_pmf_config_t {
                capable: false,
                required: false,
            },
            ..Default::default()
        };

        set_str(&mut result.ssid, conf.ssid.as_ref());
        set_str(&mut result.password, conf.password.as_ref());

        Newtype(result)
    }
}

impl From<Newtype<wifi_sta_config_t>> for ClientConfiguration {
    fn from(conf: Newtype<wifi_sta_config_t>) -> Self {
        Self {
            ssid: from_cstr(&conf.0.ssid).into(),
            bssid: if conf.0.bssid_set {
                Some(conf.0.bssid)
            } else {
                None
            },
            auth_method: Newtype(conf.0.threshold.authmode).into(),
            password: from_cstr(&conf.0.password).into(),
            channel: if conf.0.channel != 0 {
                Some(conf.0.channel)
            } else {
                None
            },
            ip_conf: None, // This must be set at a later stage
        }
    }
}

impl From<&AccessPointConfiguration> for Newtype<wifi_ap_config_t> {
    fn from(conf: &AccessPointConfiguration) -> Self {
        let mut result = wifi_ap_config_t {
            ssid: [0; 32],
            password: [0; 64],
            ssid_len: conf.ssid.len() as u8,
            channel: conf.channel,
            authmode: Newtype::<wifi_auth_mode_t>::from(conf.auth_method).0,
            ssid_hidden: if conf.ssid_hidden { 1 } else { 0 },
            max_connection: cmp::max(conf.max_connections, 16) as u8,
            beacon_interval: 100,
            ..Default::default()
        };

        set_str(&mut result.ssid, conf.ssid.as_ref());
        set_str(&mut result.password, conf.password.as_ref());

        Newtype(result)
    }
}

impl From<Newtype<wifi_ap_config_t>> for AccessPointConfiguration {
    fn from(conf: Newtype<wifi_ap_config_t>) -> Self {
        Self {
            ssid: if conf.0.ssid_len == 0 {
                from_cstr(&conf.0.ssid).into()
            } else {
                unsafe {
                    core::str::from_utf8_unchecked(&conf.0.ssid[0..conf.0.ssid_len as usize]).into()
                }
            },
            ssid_hidden: conf.0.ssid_hidden != 0,
            channel: conf.0.channel,
            secondary_channel: None,
            auth_method: AuthMethod::from(Newtype(conf.0.authmode)),
            protocols: EnumSet::<Protocol>::empty(), // TODO
            password: from_cstr(&conf.0.password).into(),
            max_connections: conf.0.max_connection as u16,
            ip_conf: None, // This must be set at a later stage
        }
    }
}

impl From<Newtype<&wifi_ap_record_t>> for AccessPointInfo {
    #[allow(non_upper_case_globals)]
    fn from(ap_info: Newtype<&wifi_ap_record_t>) -> Self {
        let a = ap_info.0;

        Self {
            ssid: from_cstr(&a.ssid).into(),
            bssid: a.bssid,
            channel: a.primary,
            secondary_channel: match a.second {
                wifi_second_chan_t_WIFI_SECOND_CHAN_NONE => SecondaryChannel::None,
                wifi_second_chan_t_WIFI_SECOND_CHAN_ABOVE => SecondaryChannel::Above,
                wifi_second_chan_t_WIFI_SECOND_CHAN_BELOW => SecondaryChannel::Below,
                _ => panic!(),
            },
            signal_strength: a.rssi as u8,
            protocols: EnumSet::<Protocol>::empty(), // TODO
            auth_method: AuthMethod::from(Newtype::<wifi_auth_mode_t>(a.authmode)),
        }
    }
}

static TAKEN: mutex::Mutex<bool> = mutex::Mutex::new(false);

struct Shared {
    client_ip_conf: Option<ipv4::ClientConfiguration>,
    router_ip_conf: Option<ipv4::RouterConfiguration>,

    status: Status,
    operating: bool,

    sta_netif: Option<EspNetif>,
    ap_netif: Option<EspNetif>,

    #[cfg(feature = "experimental")]
    on_disconnect_client: Option<Box<dyn FnMut()>>,
    #[cfg(feature = "experimental")]
    status_change_wakers: WakerRegistry,
    #[cfg(feature = "experimental")]
    last_wifi_event: Option<WifiEvent>,
}

impl Shared {
    fn is_our_sta_ip_event(&self, event: &IpEvent) -> bool {
        self.sta_netif.is_some()
            && self.sta_netif.as_ref().map(|netif| netif.1)
                == event.handle().map(|handle| handle as _)
    }

    fn is_our_ap_ip_event(&self, event: &IpEvent) -> bool {
        self.ap_netif.is_some()
            && self.ap_netif.as_ref().map(|netif| netif.1)
                == event.handle().map(|handle| handle as _)
    }
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            client_ip_conf: None,
            router_ip_conf: None,
            status: Status(ClientStatus::Stopped, ApStatus::Stopped),
            operating: false,
            sta_netif: None,
            ap_netif: None,

            #[cfg(feature = "experimental")]
            on_disconnect_client: Default::default(),
            #[cfg(feature = "experimental")]
            status_change_wakers: WakerRegistry::new(),
            #[cfg(feature = "experimental")]
            last_wifi_event: None,
        }
    }
}

unsafe impl Send for Shared {}

pub struct EspWifi {
    netif_stack: Arc<EspNetifStack>,
    sys_loop_stack: Arc<EspSysLoopStack>,
    _nvs: Arc<EspDefaultNvs>,

    waitable: Arc<Waitable<Shared>>,

    _wifi_subscription: EspSubscription<System>,
    _ip_subscription: EspSubscription<System>,
}

impl EspWifi {
    pub fn new(
        netif_stack: Arc<EspNetifStack>,
        sys_loop_stack: Arc<EspSysLoopStack>,
        nvs: Arc<EspDefaultNvs>,
    ) -> Result<Self, EspError> {
        let mut taken = TAKEN.lock();

        if *taken {
            esp!(ESP_ERR_INVALID_STATE as i32)?;
        }

        let wifi = Self::init(netif_stack, sys_loop_stack, nvs)?;

        *taken = true;
        Ok(wifi)
    }

    fn init(
        netif_stack: Arc<EspNetifStack>,
        sys_loop_stack: Arc<EspSysLoopStack>,
        nvs: Arc<EspDefaultNvs>,
    ) -> Result<Self, EspError> {
        #[allow(clippy::needless_update)]
        let cfg = wifi_init_config_t {
            #[cfg(esp_idf_version_major = "4")]
            event_handler: Some(esp_event_send_internal),
            osi_funcs: unsafe { &mut g_wifi_osi_funcs },
            wpa_crypto_funcs: unsafe { g_wifi_default_wpa_crypto_funcs },
            static_rx_buf_num: CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM as _,
            dynamic_rx_buf_num: CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM as _,
            tx_buf_type: CONFIG_ESP32_WIFI_TX_BUFFER_TYPE as _,
            static_tx_buf_num: WIFI_STATIC_TX_BUFFER_NUM as _,
            dynamic_tx_buf_num: WIFI_DYNAMIC_TX_BUFFER_NUM as _,
            cache_tx_buf_num: WIFI_CACHE_TX_BUFFER_NUM as _,
            csi_enable: WIFI_CSI_ENABLED as _,
            ampdu_rx_enable: WIFI_AMPDU_RX_ENABLED as _,
            ampdu_tx_enable: WIFI_AMPDU_TX_ENABLED as _,
            amsdu_tx_enable: WIFI_AMSDU_TX_ENABLED as _,
            nvs_enable: WIFI_NVS_ENABLED as _,
            nano_enable: WIFI_NANO_FORMAT_ENABLED as _,
            //tx_ba_win: WIFI_DEFAULT_TX_BA_WIN as _,
            rx_ba_win: WIFI_DEFAULT_RX_BA_WIN as _,
            wifi_task_core_id: WIFI_TASK_CORE_ID as _,
            beacon_max_len: WIFI_SOFTAP_BEACON_MAX_LEN as _,
            mgmt_sbuf_num: WIFI_MGMT_SBUF_NUM as _,
            feature_caps: unsafe { g_wifi_feature_caps },
            sta_disconnected_pm: WIFI_STA_DISCONNECTED_PM_ENABLED != 0,
            magic: WIFI_INIT_CONFIG_MAGIC as _,
            ..Default::default()
        };
        esp!(unsafe { esp_wifi_init(&cfg) })?;

        info!("Driver initialized");

        let waitable: Arc<Waitable<Shared>> = Arc::new(Waitable::new(Default::default()));

        let wifi_waitable = waitable.clone();
        let wifi_subscription =
            sys_loop_stack
                .get_loop()
                .clone()
                .subscribe(move |event: &WifiEvent| {
                    let mut shared = wifi_waitable.state.lock();

                    if Self::on_wifi_event(&mut shared, event).unwrap() {
                        wifi_waitable.cvar.notify_all();
                    }
                })?;

        let ip_waitable = waitable.clone();
        let ip_subscription =
            sys_loop_stack
                .get_loop()
                .clone()
                .subscribe(move |event: &IpEvent| {
                    let mut shared = ip_waitable.state.lock();

                    if Self::on_ip_event(&mut shared, event).unwrap() {
                        ip_waitable.cvar.notify_all();
                    }
                })?;

        info!("Event handlers registered");

        let wifi = Self {
            netif_stack,
            sys_loop_stack,
            _nvs: nvs,
            waitable,
            _wifi_subscription: wifi_subscription,
            _ip_subscription: ip_subscription,
        };

        info!("Initialization complete");

        Ok(wifi)
    }

    pub fn with_client_netif<F, T>(&self, f: F) -> T
    where
        F: FnOnce(Option<&EspNetif>) -> T,
    {
        self.waitable.get(|shared| f(shared.sta_netif.as_ref()))
    }

    pub fn with_client_netif_mut<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(Option<&mut EspNetif>) -> T,
    {
        self.waitable.get_mut(|shared| f(shared.sta_netif.as_mut()))
    }

    pub fn with_router_netif<F, T>(&self, f: F) -> T
    where
        F: FnOnce(Option<&EspNetif>) -> T,
    {
        self.waitable.get(|shared| f(shared.ap_netif.as_ref()))
    }

    pub fn with_router_netif_mut<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(Option<&mut EspNetif>) -> T,
    {
        self.waitable.get_mut(|shared| f(shared.ap_netif.as_mut()))
    }

    fn get_client_conf(&self) -> Result<ClientConfiguration, EspError> {
        let mut wifi_config: wifi_config_t = Default::default();
        esp!(unsafe { esp_wifi_get_config(wifi_interface_t_WIFI_IF_STA, &mut wifi_config) })?;

        let mut result: ClientConfiguration = unsafe { Newtype(wifi_config.sta).into() };
        result.ip_conf = self.waitable.get(|shared| shared.client_ip_conf.clone());

        info!("Providing STA configuration: {:?}", &result);

        Ok(result)
    }

    fn set_client_conf(&mut self, conf: &ClientConfiguration) -> Result<(), EspError> {
        info!("Setting STA configuration: {:?}", conf);

        let mut wifi_config = wifi_config_t {
            sta: Newtype::<wifi_sta_config_t>::from(conf).0,
        };

        esp!(unsafe { esp_wifi_set_config(wifi_interface_t_WIFI_IF_STA, &mut wifi_config) })?;

        self.set_client_ip_conf(&conf.ip_conf)?;

        info!("STA configuration done");

        Ok(())
    }

    fn get_ap_conf(&self) -> Result<AccessPointConfiguration, EspError> {
        let mut wifi_config: wifi_config_t = Default::default();
        esp!(unsafe { esp_wifi_get_config(wifi_interface_t_WIFI_IF_AP, &mut wifi_config) })?;

        let mut result: AccessPointConfiguration = unsafe { Newtype(wifi_config.ap).into() };
        result.ip_conf = self.waitable.get(|shared| shared.router_ip_conf);

        info!("Providing AP configuration: {:?}", &result);

        Ok(result)
    }

    fn set_ap_conf(&mut self, conf: &AccessPointConfiguration) -> Result<(), EspError> {
        info!("Setting AP configuration: {:?}", conf);

        let mut wifi_config = wifi_config_t {
            ap: Newtype::<wifi_ap_config_t>::from(conf).0,
        };

        esp!(unsafe { esp_wifi_set_config(wifi_interface_t_WIFI_IF_AP, &mut wifi_config) })?;

        self.set_router_ip_conf(&conf.ip_conf)?;

        info!("AP configuration done");

        Ok(())
    }

    fn set_client_ip_conf(
        &mut self,
        conf: &Option<ipv4::ClientConfiguration>,
    ) -> Result<(), EspError> {
        let mut shared = self.waitable.state.lock();
        Self::netif_unbind(shared.sta_netif.as_mut())?;

        let netif = if let Some(conf) = conf {
            let mut iconf = InterfaceConfiguration::wifi_default_client();
            iconf.ip_configuration = InterfaceIpConfiguration::Client(conf.clone());

            info!("Setting STA interface configuration: {:?}", iconf);

            let netif = match shared.sta_netif.take() {
                Some(netif) => netif,
                None => EspNetif::new(self.netif_stack.clone(), &iconf)?,
            };

            esp!(unsafe { esp_netif_attach_wifi_station(netif.1) })?;
            esp!(unsafe { esp_wifi_set_default_wifi_sta_handlers() })?;

            info!("STA IP configuration done");

            Some(netif)
        } else {
            info!("Skipping STA IP configuration (not configured)");

            None
        };

        shared.client_ip_conf = conf.clone();
        shared.sta_netif = netif;

        Ok(())
    }

    fn set_router_ip_conf(
        &mut self,
        conf: &Option<ipv4::RouterConfiguration>,
    ) -> Result<(), EspError> {
        let mut shared = self.waitable.state.lock();
        Self::netif_unbind(shared.ap_netif.as_mut())?;

        let netif = if let Some(conf) = conf {
            let mut iconf = InterfaceConfiguration::wifi_default_router();
            iconf.ip_configuration = InterfaceIpConfiguration::Router(*conf);

            info!("Setting AP interface configuration: {:?}", iconf);

            let netif = match shared.ap_netif.take() {
                Some(netif) => netif,
                None => EspNetif::new(self.netif_stack.clone(), &iconf)?,
            };

            esp!(unsafe { esp_netif_attach_wifi_ap(netif.1) })?;
            esp!(unsafe { esp_wifi_set_default_wifi_ap_handlers() })?;

            info!("AP IP configuration done");

            Some(netif)
        } else {
            info!("Skipping AP IP configuration (not configured)");

            None
        };

        shared.router_ip_conf = *conf;
        shared.ap_netif = netif;

        Ok(())
    }

    pub fn wait_status(&self, matcher: impl Fn(&Status) -> bool) {
        info!("About to wait for status");

        self.waitable.wait_while(|shared| !matcher(&shared.status));

        info!("Waiting for status done - success");
    }

    pub fn wait_status_with_timeout(
        &self,
        dur: Duration,
        matcher: impl Fn(&Status) -> bool,
    ) -> Result<(), Status> {
        info!("About to wait {:?} for status", dur);

        let (timeout, status) = self.waitable.wait_timeout_while_and_get(
            dur,
            |shared| !matcher(&shared.status),
            |shared| shared.status.clone(),
        );

        if !timeout {
            info!("Waiting for status done - success");
            Ok(())
        } else {
            info!("Timeout while waiting for status");
            Err(status)
        }
    }

    fn start(&mut self, status: Status, wait: Option<Duration>) -> Result<(), EspError> {
        info!("Starting with status: {:?}", status);

        {
            let mut shared = self.waitable.state.lock();

            shared.status = status.clone();
            shared.operating = false; // status.is_operating();

            if status.is_operating() {
                info!("Status is of operating type, starting");

                esp!(unsafe { esp_wifi_start() })?;

                info!("Start requested");

                Self::netif_info("STA", shared.sta_netif.as_ref())?;
                Self::netif_info("AP", shared.ap_netif.as_ref())?;
            } else {
                info!("Status is NOT of operating type, not starting");
            }
        }

        if let Some(duration) = wait {
            let result = self.wait_status_with_timeout(duration, |s| !s.is_transitional());

            if result.is_err() {
                info!("Timeout while waiting for the requested state");

                return Err(EspError::from(ESP_ERR_TIMEOUT as i32).unwrap());
            }

            info!("Started");
        }

        Ok(())
    }

    fn stop(&mut self, wait: bool) -> Result<(), EspError> {
        info!("Stopping");

        {
            let mut shared = self.waitable.state.lock();

            shared.operating = false;

            esp!(unsafe { esp_wifi_disconnect() }).or_else(|err| {
                if err.code() == esp_idf_sys::ESP_ERR_WIFI_NOT_STARTED as esp_err_t {
                    Ok(())
                } else {
                    Err(err)
                }
            })?;
            info!("Disconnect requested");

            esp!(unsafe { esp_wifi_stop() })?;
            info!("Stop requested");
        }

        if wait {
            self.wait_status(|s| matches!(s, Status(ClientStatus::Stopped, ApStatus::Stopped)));
        }

        info!("Stopped");

        Ok(())
    }

    fn clear_all(&mut self) -> Result<(), EspError> {
        self.stop(true)?;

        let mut shared = self.waitable.state.lock();

        unsafe {
            Self::netif_unbind(shared.ap_netif.as_mut())?;
            shared.ap_netif = None;

            Self::netif_unbind(shared.sta_netif.as_mut())?;
            shared.sta_netif = None;

            info!("Event handlers deregistered");

            esp!(esp_wifi_deinit())?;

            info!("Driver deinitialized");
        }

        info!("Deinitialization complete");

        Ok(())
    }

    #[allow(non_upper_case_globals)]
    fn do_scan(&mut self) -> Result<usize, EspError> {
        info!("About to scan for access points");

        self.stop(true)?;

        unsafe {
            esp!(esp_wifi_set_mode(wifi_mode_t_WIFI_MODE_STA))?;
            esp!(esp_wifi_start())?;

            esp!(esp_wifi_scan_start(ptr::null_mut(), true))?;
        }

        let mut found_ap: u16 = 0;
        esp!(unsafe { esp_wifi_scan_get_ap_num(&mut found_ap as *mut _) })?;

        info!("Found {} access points", found_ap);

        Ok(found_ap as usize)
    }

    #[allow(non_upper_case_globals)]
    fn do_get_scan_infos(
        &mut self,
        ap_infos_raw: &mut [wifi_ap_record_t],
    ) -> Result<usize, EspError> {
        info!("About to get info for found access points");

        let mut ap_count: u16 = ap_infos_raw.len() as u16;

        esp!(unsafe { esp_wifi_scan_get_ap_records(&mut ap_count, ap_infos_raw.as_mut_ptr(),) })?;

        info!("Got info for {} access points", ap_count);

        Ok(ap_count as usize)
    }

    fn netif_unbind(netif: Option<&mut EspNetif>) -> Result<(), EspError> {
        if let Some(netif) = netif {
            esp!(unsafe {
                esp_wifi_clear_default_wifi_driver_and_handlers(netif.1 as *mut c_types::c_void)
            })?;
        }

        Ok(())
    }

    fn netif_info(name: &'static str, netif: Option<&EspNetif>) -> Result<(), EspError> {
        if let Some(netif) = netif {
            info!(
                "{} netif status: {:?}, index: {}, name: {}, ifkey: {}",
                name,
                netif,
                netif.get_index(),
                netif.get_name(),
                netif.get_key()
            );
        } else {
            info!("{} netif is not allocated", name);
        }

        Ok(())
    }

    fn on_wifi_event(shared: &mut Shared, event: &WifiEvent) -> Result<bool, EspError> {
        info!("Got wifi event: {:?}", event);

        let (client_status, ap_status) = match event {
            WifiEvent::StaStarted => (Some(Self::reconnect_if_operating(shared.operating)?), None),
            WifiEvent::StaStopped => (Some(ClientStatus::Stopped), None),
            WifiEvent::StaConnected => (
                Some(ClientStatus::Started(ClientConnectionStatus::Connected(
                    match shared.client_ip_conf.as_ref() {
                        None => ClientIpStatus::Disabled,
                        Some(ipv4::ClientConfiguration::DHCP(_)) => ClientIpStatus::Waiting,
                        Some(ipv4::ClientConfiguration::Fixed(ref status)) => {
                            ClientIpStatus::Done(*status)
                        }
                    },
                ))),
                None,
            ),
            WifiEvent::StaDisconnected => {
                #[cfg(feature = "experimental")]
                {
                    if let Some(func) = shared.on_disconnect_client.as_mut() {
                        func()
                    }
                }
                (Some(Self::reconnect_if_operating(shared.operating)?), None)
            }
            WifiEvent::ApStarted => (None, Some(ApStatus::Started(ApIpStatus::Done))),
            WifiEvent::ApStopped => (None, Some(ApStatus::Stopped)),
            _ => (None, None),
        };

        let ret = if client_status.is_some() || ap_status.is_some() {
            if let Some(client_status) = client_status {
                shared.status.0 = client_status;
            }

            if let Some(ap_status) = ap_status {
                shared.status.1 = ap_status;
            }

            info!(
                "STA event {:?} handled, set status: {:?}",
                event, shared.status
            );

            Ok(true)
        } else {
            info!("STA event {:?} skipped", event);

            Ok(false)
        };

        #[cfg(feature = "experimental")]
        {
            let _ = shared.last_wifi_event.insert(event.to_owned());
            shared.status_change_wakers.awake_all();
        }

        ret
    }

    fn on_ip_event(shared: &mut Shared, event: &IpEvent) -> Result<bool, EspError> {
        if shared.is_our_sta_ip_event(event) {
            info!("Got STA IP event: {:?}", event);

            let status = match event {
                IpEvent::DhcpIpAssigned(assignment) => Some(ClientStatus::Started(
                    ClientConnectionStatus::Connected(ClientIpStatus::Done(assignment.ip_settings)),
                )),
                IpEvent::DhcpIpDeassigned(_) => Some(ClientStatus::Started(
                    ClientConnectionStatus::Connected(ClientIpStatus::Waiting),
                )),
                _ => None,
            };

            if let Some(status) = status {
                if matches!(event, IpEvent::DhcpIpDeassigned(_)) {
                    shared.status.0 = Self::reconnect_if_operating(shared.operating)?;
                } else {
                    shared.status.0 = status;
                    #[cfg(feature = "experimental")]
                    shared.status_change_wakers.awake_all();
                }

                info!(
                    "STA IP event {:?} handled, set status: {:?}",
                    event, shared.status
                );

                Ok(true)
            } else {
                info!("STA IP event {:?} skipped", event);

                Ok(false)
            }
        } else if shared.is_our_ap_ip_event(event) {
            info!("Got AP IP event: {:?}", event);

            info!("AP IP event {:?} skipped", event);

            Ok(false)
        } else {
            Ok(false)
        }
    }

    fn reconnect_if_operating(operating: bool) -> Result<ClientStatus, EspError> {
        Ok(if operating {
            info!("Reconnecting");

            esp_nofail!(unsafe { esp_wifi_connect() });

            ClientStatus::Started(ClientConnectionStatus::Connecting)
        } else {
            ClientStatus::Started(ClientConnectionStatus::Disconnected)
        })
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum Mode {
    None,
    SoftAp,
    Client,
    ApClient,
}

#[derive(Debug, Clone, Copy)]
enum TransitionState {
    None,
    Full,
    Half,
}

impl Mode {
    pub fn starting_status(&self) -> Status {
        match self {
            Self::None => Status(ClientStatus::Stopped, ApStatus::Stopped),
            Self::SoftAp => Status(ClientStatus::Stopped, ApStatus::Starting),
            Self::Client => Status(ClientStatus::Starting, ApStatus::Stopped),
            Self::ApClient => Status(ClientStatus::Starting, ApStatus::Starting),
        }
    }

    pub fn has_status_successfully_transitioned(&self, status: &Status) -> TransitionState {
        match self {
            Self::None => {
                if let Status(ClientStatus::Stopped, ApStatus::Stopped) = status {
                    return TransitionState::Full;
                }
            }
            Self::SoftAp => {
                if let Status(ClientStatus::Stopped, ApStatus::Started(_)) = status {
                    return TransitionState::Full;
                }
            }
            Self::Client => {
                if let Status(ClientStatus::Started(_), ApStatus::Stopped) = status {
                    return TransitionState::Full;
                }
            }
            Self::ApClient => match status {
                Status(ClientStatus::Started(_), ApStatus::Started(_)) => {
                    return TransitionState::Full
                }
                Status(ClientStatus::Started(_), _) => return TransitionState::Half,
                Status(_, ApStatus::Started(_)) => return TransitionState::Half,
                _ => (),
            },
        }

        TransitionState::None
    }
}

impl From<Configuration> for Mode {
    fn from(c: Configuration) -> Self {
        match c {
            Configuration::None => Mode::None,
            Configuration::AccessPoint(_) => Mode::SoftAp,
            Configuration::Client(_) => Mode::Client,
            Configuration::Mixed(_, _) => Mode::ApClient,
        }
    }
}

#[cfg(feature = "experimental")]
impl EspWifi {
    pub fn set_callback_on_disconnect<F: FnMut() + 'static>(&mut self, callback: F) {
        let mut shared = self.waitable.state.lock();
        let _ = shared.on_disconnect_client.insert(Box::new(callback));
    }

    pub fn wait_for_wifi_event(&mut self, event: WifiEvent) -> impl Future<Output = WifiEvent> {
        EventOccureFuture::new(self.waitable.to_owned(), Some(event))
    }

    /// Scans for available accesspoints.
    ///
    /// To call this function, the wifi must be configured in accesspoint mode or at least in mixed mode.
    pub async fn async_scan(
        &mut self,
        scan_config: Option<ScanConfig>,
    ) -> Result<alloc::vec::Vec<AccessPointInfo>, EspError> {
        let total_count = self.async_do_scan(scan_config).await?;

        let mut ap_infos_raw: alloc::vec::Vec<wifi_ap_record_t> =
            alloc::vec::Vec::with_capacity(total_count as usize);
        #[allow(clippy::uninit_vec)]
        // ... because we are filling it in on the next line and only reading the initialized members
        unsafe {
            ap_infos_raw.set_len(total_count as usize)
        };

        let real_count = self.do_get_scan_infos(&mut ap_infos_raw)?;

        let mut result = alloc::vec::Vec::with_capacity(real_count);
        for ap_info_raw in ap_infos_raw.iter().take(real_count) {
            let ap_info: AccessPointInfo = Newtype(ap_info_raw).into();

            result.push(ap_info);
        }

        Ok(result)
    }

    /// ## Prerequests:
    /// - mode: Client
    /// - configured Accesspoint
    pub async fn async_connect_to_accesspoint(
        &mut self,
    ) -> Result<Option<ClientIpStatus>, EspError> {
        {
            let mut shared = self.waitable.state.lock();
            shared.status.0 = ClientStatus::Started(ClientConnectionStatus::Connecting);
        }

        let status_change_poller = StatusChangeFuture::new(self.waitable.to_owned());
        info!("start connecting to accesspoint");
        esp_nofail!(unsafe { esp_wifi_connect() });

        info!("wait for connection established");
        let ip = loop {
            let status = status_change_poller.to_owned().await;
            info!("got status {:?}", status);
            if !status.is_transitional() {
                match status {
                    Status(ClientStatus::Started(ClientConnectionStatus::Connected(ip)), _) => {
                        break Some(ip.to_owned())
                    }
                    _ => break None,
                }
            }
        };

        Ok(ip)
    }

    pub async fn async_disable_ap(&mut self) -> Result<(), EspError> {
        info!("Disable Accesspoint");

        let status_change_poller = StatusChangeFuture::new(self.waitable.to_owned());
        esp!(unsafe { esp_wifi_set_mode(wifi_mode_t_WIFI_MODE_STA) })?;
        if let Status(_, ApStatus::Stopped) = status_change_poller.await {
            info!("Accesspoint disabled");
            Ok(())
        } else {
            Err(EspError::from(ESP_ERR_TIMEOUT as i32).unwrap())
        }
    }

    /// Starts WIFI.
    ///
    /// The WIFI must be configured with specific config before. The
    /// param `mode` indicates on which event the function should wait until WIFI is
    /// successfully turned on.
    ///
    /// This function returns when WIFI has successfully started. If not one of the correct
    /// events are received, the function returns with an error `ESP_ERR_TIMEOUT`.
    async fn async_start_wifi(&mut self, mode: Mode) -> Result<(), EspError> {
        info!("Start in mode: {:?}", mode);
        let status_change_poller = StatusChangeFuture::new(self.waitable.to_owned());

        {
            let mut shared = self.waitable.state.lock();
            shared.status = mode.starting_status();
            esp!(unsafe { esp_wifi_start() })?;
        }

        let res = loop {
            let status = status_change_poller.to_owned().await;

            info!("new state: {:?}", status);

            match mode.has_status_successfully_transitioned(&status) {
                TransitionState::None => break Err(EspError::from(ESP_ERR_TIMEOUT as i32).unwrap()),
                TransitionState::Half => continue,
                TransitionState::Full => {
                    info!("Started");
                    break Ok(());
                }
            }
        };

        res
    }

    /// Stops WIFI.
    ///
    /// If an Accesspoint is connected it will be disconnected.
    /// Stops AP/Client (Frees AP data block).
    /// Waits till status is `Stopped` for both modes.
    /// If status not changes immediatly to `Stopped` it returns a timeout error.
    async fn async_stop(&mut self) -> Result<(), EspError> {
        info!("Stopping");

        {
            let shared = self.waitable.state.lock();
            if let Status(ClientStatus::Stopped, ApStatus::Stopped) = shared.status {
                return Ok(());
            }
        }

        let status_change_poller = StatusChangeFuture::new(self.waitable.to_owned());

        {
            let mut shared = self.waitable.state.lock();
            shared.operating = false;

            if let Status(ClientStatus::Started(ClientConnectionStatus::Connected(_)), _) =
                shared.status
            {
                esp!(unsafe { esp_wifi_disconnect() }).or_else(|err| {
                    if err.code() == esp_idf_sys::ESP_ERR_WIFI_NOT_STARTED as esp_err_t {
                        Ok(())
                    } else {
                        Err(err)
                    }
                })?;
                info!("Disconnect requested");
            }

            esp!(unsafe { esp_wifi_stop() })?;
            info!("Stop requested");
        }

        let res = loop {
            let status = status_change_poller.to_owned().await;

            match status {
                Status(ClientStatus::Stopped, ApStatus::Stopped) => {
                    info!("Stopped");
                    break Ok(());
                }
                Status(ClientStatus::Stopped, _) | Status(_, ApStatus::Stopped) => continue,
                _ => break Err(EspError::from(ESP_ERR_TIMEOUT as i32).unwrap()),
            }
        };

        res
    }

    pub async fn async_do_scan(
        &mut self,
        scan_config: Option<ScanConfig>,
    ) -> Result<usize, EspError> {
        info!(
            "About to scan for access points with config: {:?}",
            scan_config
        );

        let on_scan_finished =
            EventOccureFuture::new(self.waitable.to_owned(), Some(WifiEvent::ScanDone));

        {
            let scan_config = scan_config.map(wifi_scan_config_t::from);
            esp!(unsafe {
                esp_wifi_scan_start(
                    scan_config
                        .as_ref()
                        .map_or(ptr::null(), |s| s as *const wifi_scan_config_t),
                    false,
                )
            })?;
        }
        let _ = on_scan_finished.await;

        let mut found_ap: u16 = 0;
        esp!(unsafe { esp_wifi_scan_get_ap_num(&mut found_ap as *mut _) })?;
        info!("Found {} access points", found_ap);
        Ok(usize::from(found_ap))
    }

    fn update_ap_conf_if_new(&mut self, conf: &AccessPointConfiguration) -> Result<(), EspError> {
        match self.get_ap_conf() {
            Ok(curr_conf) if !curr_conf.eq(conf) => self.set_ap_conf(conf)?,
            _ => (),
        }

        Ok(())
    }

    fn update_client_conf_if_new(&mut self, conf: &ClientConfiguration) -> Result<(), EspError> {
        match self.get_client_conf() {
            Ok(curr_conf) if !curr_conf.eq(conf) => self.set_client_conf(conf)?,
            _ => (),
        }

        Ok(())
    }

    /// Sets a specific configuration.
    ///
    /// The given configuration will be applied. This function does not start the wifi.
    ///
    /// The parameter `configure_client` indicates for config `Configuration::Mixed` if the
    /// client configuration should be applied or not. This can be used if the board operates in
    /// accesspoint mode and the client mode is used for scanning reachable accesspoints.
    pub async fn async_set_configuration(
        &mut self,
        conf: &Configuration,
        configure_client: bool,
    ) -> Result<(), EspError> {
        info!("Setting configuration: {:?}", conf);

        unsafe {
            match conf {
                Configuration::None => {
                    esp!(esp_wifi_set_mode(wifi_mode_t_WIFI_MODE_NULL))?;
                    info!("Wifi mode NULL set");
                }
                Configuration::AccessPoint(ap_conf) => {
                    esp!(esp_wifi_set_mode(wifi_mode_t_WIFI_MODE_AP))?;
                    info!("Wifi mode AP set");
                    self.update_ap_conf_if_new(ap_conf)?;
                }
                Configuration::Client(client_conf) => {
                    esp!(esp_wifi_set_mode(wifi_mode_t_WIFI_MODE_STA))?;
                    info!("Wifi mode STA set");

                    self.update_client_conf_if_new(client_conf)?;
                }
                Configuration::Mixed(client_conf, ap_conf) => {
                    esp!(esp_wifi_set_mode(wifi_mode_t_WIFI_MODE_APSTA))?;
                    info!("Wifi mode APSTA set");

                    self.update_ap_conf_if_new(ap_conf)?;
                    if configure_client {
                        self.update_client_conf_if_new(client_conf)?;
                    }
                }
            }
        };

        Ok(())
    }

    pub async fn async_start_with_configuration(
        &mut self,
        conf: &Configuration,
        configure_client: bool,
    ) -> Result<(), EspError> {
        info!("Start configured");

        self.async_stop().await?;

        self.async_set_configuration(conf, configure_client).await?;

        let mode = Mode::from(conf.to_owned());
        self.async_start_wifi(mode).await?;

        info!("Configuration set");

        Ok(())
    }
}

impl Drop for EspWifi {
    fn drop(&mut self) {
        {
            let mut taken = TAKEN.lock();

            self.clear_all().unwrap();
            *taken = false;
        }

        info!("Dropped");
    }
}

impl Wifi for EspWifi {
    type Error = EspError;

    fn get_capabilities(&self) -> Result<EnumSet<Capability>, Self::Error> {
        let caps = Capability::Client | Capability::AccessPoint | Capability::Mixed;

        info!("Providing capabilities: {:?}", caps);

        Ok(caps)
    }

    fn get_status(&self) -> Status {
        let status = self.waitable.get(|shared| shared.status.clone());

        info!("Providing status: {:?}", status);

        status
    }

    #[allow(non_upper_case_globals)]
    fn scan_n<const N: usize>(
        &mut self,
    ) -> Result<(heapless::Vec<AccessPointInfo, N>, usize), Self::Error> {
        let total_count = self.do_scan()?;

        let mut ap_infos_raw: heapless::Vec<wifi_ap_record_t, N> = heapless::Vec::new();

        let real_count = self.do_get_scan_infos(&mut ap_infos_raw)?;

        let mut result = heapless::Vec::<_, N>::new();
        for ap_info_raw in ap_infos_raw.iter().take(real_count) {
            let ap_info: AccessPointInfo = Newtype(ap_info_raw).into();
            info!("Found access point {:?}", ap_info);

            if result.push(ap_info).is_err() {
                break;
            }
        }

        Ok((result, total_count))
    }

    #[allow(non_upper_case_globals)]
    fn scan(&mut self) -> Result<alloc::vec::Vec<AccessPointInfo>, Self::Error> {
        let total_count = self.do_scan()?;

        let mut ap_infos_raw: alloc::vec::Vec<wifi_ap_record_t> =
            alloc::vec::Vec::with_capacity(total_count as usize);

        #[allow(clippy::uninit_vec)]
        // ... because we are filling it in on the next line and only reading the initialized members
        unsafe {
            ap_infos_raw.set_len(total_count as usize)
        };

        let real_count = self.do_get_scan_infos(&mut ap_infos_raw)?;

        let mut result = alloc::vec::Vec::with_capacity(real_count);
        for ap_info_raw in ap_infos_raw.iter().take(real_count) {
            let ap_info: AccessPointInfo = Newtype(ap_info_raw).into();
            info!("Found access point {:?}", ap_info);

            result.push(ap_info);
        }

        Ok(result)
    }

    #[allow(non_upper_case_globals)]
    fn get_configuration(&self) -> Result<Configuration, Self::Error> {
        info!("Getting configuration");

        unsafe {
            let mut mode: wifi_mode_t = 0;

            esp!(esp_wifi_get_mode(&mut mode))?;

            let conf = match mode {
                wifi_mode_t_WIFI_MODE_NULL => Configuration::None,
                wifi_mode_t_WIFI_MODE_AP => Configuration::AccessPoint(self.get_ap_conf()?),
                wifi_mode_t_WIFI_MODE_STA => Configuration::Client(self.get_client_conf()?),
                wifi_mode_t_WIFI_MODE_APSTA => {
                    Configuration::Mixed(self.get_client_conf()?, self.get_ap_conf()?)
                }
                _ => panic!(),
            };

            info!("Configuration gotten: {:?}", &conf);

            Ok(conf)
        }
    }

    fn set_configuration(&mut self, conf: &Configuration) -> Result<(), Self::Error> {
        info!("Setting configuration: {:?}", conf);

        self.stop(false)?;

        let status = unsafe {
            match conf {
                Configuration::None => {
                    esp!(esp_wifi_set_mode(wifi_mode_t_WIFI_MODE_NULL))?;
                    info!("Wifi mode NULL set");

                    Status(ClientStatus::Stopped, ApStatus::Stopped)
                }
                Configuration::AccessPoint(ap_conf) => {
                    esp!(esp_wifi_set_mode(wifi_mode_t_WIFI_MODE_AP))?;
                    info!("Wifi mode AP set");

                    self.set_ap_conf(ap_conf)?;
                    Status(ClientStatus::Stopped, ApStatus::Starting)
                }
                Configuration::Client(client_conf) => {
                    esp!(esp_wifi_set_mode(wifi_mode_t_WIFI_MODE_STA))?;
                    info!("Wifi mode STA set");

                    self.set_client_conf(client_conf)?;
                    Status(ClientStatus::Starting, ApStatus::Stopped)
                }
                Configuration::Mixed(client_conf, ap_conf) => {
                    esp!(esp_wifi_set_mode(wifi_mode_t_WIFI_MODE_APSTA))?;
                    info!("Wifi mode APSTA set");

                    self.set_client_conf(client_conf)?;
                    self.set_ap_conf(ap_conf)?;
                    Status(ClientStatus::Starting, ApStatus::Starting)
                }
            }
        };

        self.start(status, None)?;

        info!("Configuration set");

        Ok(())
    }
}

unsafe impl Send for EspWifi {}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WifiEvent {
    Ready,

    ScanStarted,
    ScanDone,

    StaStarted,
    StaStopped,
    StaConnected,
    StaDisconnected,
    StaAuthmodeChanged,
    StaBssRssiLow,
    StaBeaconTimeout,
    StaWpsSuccess,
    StaWpsFailed,
    StaWpsTimeout,
    StaWpsPin,
    StaWpsPbcOverlap,

    ApStarted,
    ApStopped,
    ApStaConnected,
    ApStaDisconnected,
    ApProbeRequestReceived,

    FtmReport,
    ActionTxStatus,
    RocDone,
}

impl EspTypedEventSource for WifiEvent {
    fn source() -> *const c_types::c_char {
        unsafe { WIFI_EVENT }
    }
}

impl EspTypedEventDeserializer<WifiEvent> for WifiEvent {
    #[allow(non_upper_case_globals, non_snake_case)]
    fn deserialize<R>(
        data: &crate::eventloop::EspEventFetchData,
        f: &mut impl for<'a> FnMut(&'a WifiEvent) -> R,
    ) -> R {
        let event_id = data.event_id as u32;

        let event = if event_id == wifi_event_t_WIFI_EVENT_WIFI_READY {
            WifiEvent::Ready
        } else if event_id == wifi_event_t_WIFI_EVENT_SCAN_DONE {
            WifiEvent::ScanDone
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_START {
            WifiEvent::StaStarted
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_STOP {
            WifiEvent::StaStopped
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_CONNECTED {
            WifiEvent::StaConnected
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_DISCONNECTED {
            WifiEvent::StaDisconnected
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_AUTHMODE_CHANGE {
            WifiEvent::StaAuthmodeChanged
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_WPS_ER_SUCCESS {
            WifiEvent::StaWpsSuccess
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_WPS_ER_FAILED {
            WifiEvent::StaWpsFailed
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_WPS_ER_TIMEOUT {
            WifiEvent::StaWpsTimeout
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_WPS_ER_PIN {
            WifiEvent::StaWpsPin
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_WPS_ER_PBC_OVERLAP {
            WifiEvent::StaWpsPbcOverlap
        } else if event_id == wifi_event_t_WIFI_EVENT_AP_START {
            WifiEvent::ApStarted
        } else if event_id == wifi_event_t_WIFI_EVENT_AP_STOP {
            WifiEvent::ApStopped
        } else if event_id == wifi_event_t_WIFI_EVENT_AP_STACONNECTED {
            WifiEvent::ApStaConnected
        } else if event_id == wifi_event_t_WIFI_EVENT_AP_STADISCONNECTED {
            WifiEvent::ApStaDisconnected
        } else if event_id == wifi_event_t_WIFI_EVENT_AP_PROBEREQRECVED {
            WifiEvent::ApProbeRequestReceived
        } else if event_id == wifi_event_t_WIFI_EVENT_FTM_REPORT {
            WifiEvent::FtmReport
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_BSS_RSSI_LOW {
            WifiEvent::StaBssRssiLow
        } else if event_id == wifi_event_t_WIFI_EVENT_ACTION_TX_STATUS {
            WifiEvent::ActionTxStatus
        } else if event_id == wifi_event_t_WIFI_EVENT_STA_BEACON_TIMEOUT {
            WifiEvent::StaBeaconTimeout
        } else {
            panic!("Unknown event ID: {}", event_id);
        };

        f(&event)
    }
}

impl ErrorType for EspWifi {
    type Error = EspError;
}

impl EventBus<()> for EspWifi {
    type Subscription = (EspSubscription<System>, EspSubscription<System>);

    fn subscribe(
        &mut self,
        callback: impl for<'a> FnMut(&'a ()) + Send + 'static,
    ) -> Result<Self::Subscription, Self::Error> {
        let wifi_cb = Arc::new(UnsafeCellSendSync(UnsafeCell::new(callback)));
        let wifi_last_status = Arc::new(UnsafeCellSendSync(UnsafeCell::new(self.get_status())));
        let wifi_waitable = self.waitable.clone();

        let ip_cb = wifi_cb.clone();
        let ip_last_status = wifi_last_status.clone();
        let ip_waitable = wifi_waitable.clone();

        let subscription1 =
            self.sys_loop_stack
                .get_loop()
                .clone()
                .subscribe(move |_event: &WifiEvent| {
                    let notify = {
                        let shared = wifi_waitable.state.lock();

                        let last_status_ref = unsafe { wifi_last_status.0.get().as_mut().unwrap() };

                        if *last_status_ref != shared.status {
                            *last_status_ref = shared.status.clone();

                            true
                        } else {
                            false
                        }
                    };

                    if notify {
                        let cb_ref = unsafe { wifi_cb.0.get().as_mut().unwrap() };

                        (cb_ref)(&());
                    }
                })?;

        let subscription2 =
            self.sys_loop_stack
                .get_loop()
                .clone()
                .subscribe(move |event: &IpEvent| {
                    let notify = {
                        let shared = ip_waitable.state.lock();

                        if shared.is_our_sta_ip_event(event) || shared.is_our_ap_ip_event(event) {
                            let last_status_ref =
                                unsafe { ip_last_status.0.get().as_mut().unwrap() };

                            if *last_status_ref != shared.status {
                                *last_status_ref = shared.status.clone();

                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    };

                    if notify {
                        let cb_ref = unsafe { ip_cb.0.get().as_mut().unwrap() };

                        (cb_ref)(&());
                    }
                })?;

        Ok((subscription1, subscription2))
    }
}

#[cfg(feature = "experimental")]
pub mod asyncify {
    use core::{future::Future, task::Poll};

    use alloc::sync::Arc;
    use embedded_svc::{
        utils::asyncify::{event_bus::AsyncEventBus, Asyncify},
        wifi::Status,
    };

    use esp_idf_hal::mutex::{Condvar, Mutex};

    use crate::private::waitable::Waitable;

    use super::WifiEvent;

    impl Asyncify for super::EspWifi {
        type AsyncWrapper<S> = AsyncEventBus<(), Condvar, S>;
    }

    pub(super) struct EventOccureFuture {
        shared: Arc<Waitable<super::Shared>>,
        event: Option<WifiEvent>,
    }

    impl EventOccureFuture {
        pub fn new(shared: Arc<Waitable<super::Shared>>, event: Option<WifiEvent>) -> Self {
            let _ = shared.state.lock().last_wifi_event.take();
            Self { shared, event }
        }
    }

    impl Future for EventOccureFuture {
        type Output = WifiEvent;

        fn poll(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Self::Output> {
            let mut shared = self.shared.state.lock();
            if let Some(event) = shared.last_wifi_event.take() {
                if self.event.is_some() && event.eq(&self.event.unwrap()) || self.event.is_none() {
                    return Poll::Ready(event);
                }
            }

            shared.status_change_wakers.register(cx.waker().to_owned());
            Poll::Pending
        }
    }

    #[derive(Clone)]
    pub(super) struct StatusChangeFuture {
        shared: Arc<Waitable<super::Shared>>,
        last_status: Arc<Mutex<Status>>,
    }

    impl StatusChangeFuture {
        pub fn new(shared: Arc<Waitable<super::Shared>>) -> Self {
            let curr_status = { shared.state.lock().status.to_owned() };
            Self {
                last_status: Arc::new(Mutex::new(curr_status)),
                shared,
            }
        }
    }

    impl Future for StatusChangeFuture {
        type Output = Status;

        fn poll(
            self: core::pin::Pin<&mut Self>,
            cx: &mut core::task::Context<'_>,
        ) -> Poll<Self::Output> {
            let new_status = { self.shared.state.lock().status.to_owned() };
            if !self.last_status.lock().eq(&new_status) {
                *self.last_status.lock() = new_status.to_owned();
                return Poll::Ready(new_status);
            }
            let mut shared = self.shared.state.lock();
            shared.status_change_wakers.register(cx.waker().to_owned());
            Poll::Pending
        }
    }
}
