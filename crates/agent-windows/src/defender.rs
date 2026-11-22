use crate::model::{Kind, Spec, GUID_HYPHENS, GUID_TEXT_BYTES, HOURS_PER_DAY, MINUTES_PER_HOUR, MONTHS_PER_YEAR, SECONDS_PER_MINUTE, TIME_SHAPE};
use std::ops::Range;


pub const POWERSHELL_PATH: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";


pub const DEFENDER_MAX_OUTPUT_BYTES: usize = 65_536;


pub const DEFENDER_DEADLINE_SECONDS: u64 = 60;


pub const MIN_DEFENDER_INTERVAL_SECONDS: u64 = 300;


pub const DEFAULT_DEFENDER_INTERVAL_SECONDS: u64 = 3_600;


pub const MAX_ASR_RULES: usize = 64;


pub const MAX_ACTION: u64 = 255;


pub const MAX_TEXT_BYTES: usize = 40;


pub const DECIMAL_BASE: u32 = 10;


pub const POWERSHELL_FLAGS: [&str; 6] = ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"];


pub const SCRIPT: &str = concat!(
    "$ErrorActionPreference = 'SilentlyContinue'; ",
    "$env:Path = 'C:\\Windows\\System32;C:\\Windows'; ",
    "$env:PSModulePath = $env:SystemRoot + '\\System32\\WindowsPowerShell\\v1.0\\Modules'; ",
    "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); ",
    "[pscustomobject]@{ status = (Defender\\Get-MpComputerStatus | Microsoft.PowerShell.Utility\\Select-Object ",
    "AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected,",
    "@{Name='AntivirusSignatureLastUpdated';Expression={if ($_.AntivirusSignatureLastUpdated) ",
    "{ $_.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o') } else { $null }}},",
    "AntivirusSignatureAge,AMRunningMode); ",
    "preference = (Defender\\Get-MpPreference | Microsoft.PowerShell.Utility\\Select-Object ",
    "AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions,EnableControlledFolderAccess) } ",
    "| Microsoft.PowerShell.Utility\\ConvertTo-Json -Compress -Depth 3",
);


pub const STATUS_FIELDS: [Spec; 9] = [
    Spec {
        source: "AMServiceEnabled",
        name: "am_service_enabled",
        kind: Kind::Flag,
    },
    Spec {
        source: "AntivirusEnabled",
        name: "antivirus_enabled",
        kind: Kind::Flag,
    },
    Spec {
        source: "RealTimeProtectionEnabled",
        name: "real_time_protection_enabled",
        kind: Kind::Flag,
    },
    Spec {
        source: "BehaviorMonitorEnabled",
        name: "behavior_monitor_enabled",
        kind: Kind::Flag,
    },
    Spec {
        source: "IoavProtectionEnabled",
        name: "ioav_protection_enabled",
        kind: Kind::Flag,
    },
    Spec {
        source: "IsTamperProtected",
        name: "tamper_protected",
        kind: Kind::Flag,
    },
    Spec {
        source: "AntivirusSignatureLastUpdated",
        name: "antivirus_signature_last_updated",
        kind: Kind::Time,
    },
    Spec {
        source: "AntivirusSignatureAge",
        name: "antivirus_signature_age",
        kind: Kind::Count,
    },
    Spec {
        source: "AMRunningMode",
        name: "am_running_mode",
        kind: Kind::Text,
    },
];


pub const CONTROLLED_FOLDER_ACCESS: Spec = Spec {
    source: "EnableControlledFolderAccess",
    name: "controlled_folder_access",
    kind: Kind::Count,
};


pub const DAYS_PER_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];


pub const FEBRUARY: u32 = 2;


pub const LEAP_CYCLE: u32 = 4;


pub const LEAP_CENTURY: u32 = 100;


pub const LEAP_QUADRICENTURY: u32 = 400;


pub const YEAR_RANGE: Range<usize> = 0..4;


pub const MONTH_RANGE: Range<usize> = 5..7;


pub const DAY_RANGE: Range<usize> = 8..10;


pub const HOUR_RANGE: Range<usize> = 11..13;


pub const MINUTE_RANGE: Range<usize> = 14..16;


pub const SECOND_RANGE: Range<usize> = 17..19;


pub fn defender_args() -> Vec<String> {
    POWERSHELL_FLAGS.iter().chain([SCRIPT].iter()).map(|part| (*part).to_string()).collect()
}


pub fn is_guid(text: &str) -> bool {
    text.len() == GUID_TEXT_BYTES
        && text.bytes().enumerate().all(|(index, byte)| {
            if GUID_HYPHENS.contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}


pub fn digits_value(text: &str, range: Range<usize>) -> u32 {
    text.get(range).map_or(0, |part| {
        part.bytes()
            .fold(0, |total, byte| total * DECIMAL_BASE + u32::from(byte.saturating_sub(b'0')))
    })
}


pub fn is_leap(year: u32) -> bool {
    year.is_multiple_of(LEAP_CYCLE) && (!year.is_multiple_of(LEAP_CENTURY) || year.is_multiple_of(LEAP_QUADRICENTURY))
}


pub fn days_in_month(year: u32, month: u32) -> u32 {
    let base = DAYS_PER_MONTH.get(month.saturating_sub(1) as usize).copied().unwrap_or(0);
    base + u32::from(month == FEBRUARY && is_leap(year))
}


pub fn is_utc_time(text: &str) -> bool {
    let shaped = text
        .bytes()
        .map(|byte| if byte.is_ascii_digit() { b'D' } else { byte })
        .eq(TIME_SHAPE.bytes());
    let year = digits_value(text, YEAR_RANGE);
    let month = digits_value(text, MONTH_RANGE);
    let day = digits_value(text, DAY_RANGE);
    let dated = (1..=MONTHS_PER_YEAR).contains(&month) && (1..=days_in_month(year, month)).contains(&day);
    let timed = digits_value(text, HOUR_RANGE) < HOURS_PER_DAY
        && digits_value(text, MINUTE_RANGE) < MINUTES_PER_HOUR
        && digits_value(text, SECOND_RANGE) < SECONDS_PER_MINUTE;
    shaped && dated && timed
}
