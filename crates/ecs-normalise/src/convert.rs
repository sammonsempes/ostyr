use crate::error::NormaliseError;
use crate::tetragon::{Envelope, KprobeBody, Process, ProcessBody};
use crate::types::Handler;
use core_export::ecs::{
    blank_event, EcsEvent, EndpointFields, EventFields, FileFields, HostFields, NetworkFields, OsFields, ParentFields, ProcessFields, UserFields,
};
use serde_json::{from_value, Value};
use time::OffsetDateTime;


pub const EXEC_KIND: &str = "process_exec";


pub const EXIT_KIND: &str = "process_exit";


pub const KPROBE_KIND: &str = "process_kprobe";


pub const NO_KIND: &str = "<none>";


pub const TCP_CONNECT_HOOK: &str = "tcp_connect";


pub const FD_INSTALL_HOOK: &str = "fd_install";


pub const FILE_HOOK_PREFIX: &str = "security_file_";


pub const MODULE: &str = "tetragon";


pub const OS_TYPE: &str = "linux";


const HANDLERS: [(&str, Handler); 3] = [(EXEC_KIND, handle_exec), (EXIT_KIND, handle_exit), (KPROBE_KIND, handle_kprobe)];


/// The result of one well-formed line: an ECS event, or the name of an event kind the normaliser does not map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Event(Box<EcsEvent>),
    Unknown(String),
}


fn base_event(time: OffsetDateTime, node_name: Option<String>) -> EcsEvent {
    EcsEvent {
        event: EventFields {
            kind: Some("event".to_string()),
            module: Some(MODULE.to_string()),
            ..EventFields::default()
        },
        host: Some(HostFields {
            name: node_name,
            os: Some(OsFields {
                kind: Some(OS_TYPE.to_string()),
            }),
            ..HostFields::default()
        }),
        ..blank_event(time)
    }
}


fn classify(base: EcsEvent, category: &str, kind_type: &str, action: &str) -> EcsEvent {
    EcsEvent {
        event: EventFields {
            category: vec![category.to_string()],
            types: vec![kind_type.to_string()],
            action: Some(action.to_string()),
            dataset: Some(format!("{MODULE}.{category}")),
            ..base.event.clone()
        },
        ..base
    }
}


fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}


fn command_line(process: &Process) -> String {
    process
        .arguments
        .as_deref()
        .filter(|arguments| !arguments.is_empty())
        .map_or_else(|| process.binary.clone(), |arguments| format!("{} {arguments}", process.binary))
}


fn add_label(event: &mut EcsEvent, key: &str, value: &str) {
    if !value.is_empty() {
        event.labels.insert(key.to_string(), value.to_string());
    }
}


fn add_process(event: &mut EcsEvent, process: &Process, parent: Option<&Process>) {
    event.process = Some(ProcessFields {
        pid: Some(process.pid),
        name: Some(base_name(&process.binary).to_string()),
        executable: Some(process.binary.clone()),
        command_line: Some(command_line(process)),
        args: process
            .arguments
            .iter()
            .flat_map(|arguments| arguments.split_whitespace())
            .map(String::from)
            .collect(),
        working_directory: process.cwd.clone(),
        parent: parent.map(|parent_process| ParentFields {
            pid: Some(parent_process.pid),
            executable: Some(parent_process.binary.clone()),
            command_line: Some(command_line(parent_process)),
            ..ParentFields::default()
        }),
        ..ProcessFields::default()
    });
    event.user = process.uid.map(|uid| UserFields {
        id: Some(uid.to_string()),
        ..UserFields::default()
    });
    process.pod.iter().for_each(|pod| {
        add_label(event, "pod_name", &pod.name);
        add_label(event, "pod_namespace", &pod.namespace);
        pod.container.iter().for_each(|container| {
            add_label(event, "container_id", &container.id);
            add_label(event, "container_name", &container.name);
        });
    });
}


fn process_event(body: Value, base: EcsEvent, kind_type: &str, action: &str) -> Result<Outcome, NormaliseError> {
    let parsed: ProcessBody = from_value(body).map_err(NormaliseError::Schema)?;
    let mut event = classify(base, "process", kind_type, action);
    add_process(&mut event, &parsed.process, parsed.parent.as_ref());
    Ok(Outcome::Event(Box::new(event)))
}


fn handle_exec(body: Value, base: EcsEvent) -> Result<Outcome, NormaliseError> {
    process_event(body, base, "start", "exec")
}


fn handle_exit(body: Value, base: EcsEvent) -> Result<Outcome, NormaliseError> {
    process_event(body, base, "end", "exit")
}


fn file_event(probe: &KprobeBody, base: EcsEvent) -> Result<Outcome, NormaliseError> {
    let file = probe
        .args
        .iter()
        .find_map(|arg| arg.file_arg.as_ref())
        .ok_or(NormaliseError::MissingField("file_arg"))?;
    let mut event = EcsEvent {
        file: Some(FileFields {
            path: Some(file.path.clone()),
            name: Some(base_name(&file.path).to_string()),
            ..FileFields::default()
        }),
        ..classify(base, "file", "access", &probe.function_name)
    };
    add_process(&mut event, &probe.process, probe.parent.as_ref());
    Ok(Outcome::Event(Box::new(event)))
}


fn network_event(probe: &KprobeBody, base: EcsEvent) -> Result<Outcome, NormaliseError> {
    let socket = probe
        .args
        .iter()
        .find_map(|arg| arg.sock_arg.as_ref())
        .ok_or(NormaliseError::MissingField("sock_arg"))?;
    let mut event = EcsEvent {
        source: Some(EndpointFields {
            ip: Some(socket.saddr.clone()),
            port: Some(socket.sport),
            domain: None,
        }),
        destination: Some(EndpointFields {
            ip: Some(socket.daddr.clone()),
            port: Some(socket.dport),
            domain: None,
        }),
        network: Some(NetworkFields {
            transport: Some("tcp".to_string()),
            direction: Some("egress".to_string()),
        }),
        ..classify(base, "network", "connection", "connect")
    };
    add_process(&mut event, &probe.process, probe.parent.as_ref());
    Ok(Outcome::Event(Box::new(event)))
}


fn handle_kprobe(body: Value, base: EcsEvent) -> Result<Outcome, NormaliseError> {
    let probe: KprobeBody = from_value(body).map_err(NormaliseError::Schema)?;
    if probe.function_name == FD_INSTALL_HOOK || probe.function_name.starts_with(FILE_HOOK_PREFIX) {
        file_event(&probe, base)
    } else if probe.function_name == TCP_CONNECT_HOOK {
        network_event(&probe, base)
    } else {
        Ok(Outcome::Unknown(format!("{KPROBE_KIND}:{}", probe.function_name)))
    }
}


/// Maps one parsed envelope to an ECS event, or reports the unmapped kind.
pub fn convert(envelope: Envelope) -> Result<Outcome, NormaliseError> {
    let Envelope { time, node_name, mut kinds } = envelope;
    let found = HANDLERS
        .iter()
        .find_map(|(name, handler)| kinds.remove(*name).map(|body| (*handler, body)));
    match found {
        Some((handler, body)) => handler(body, base_event(time, node_name)),
        None => Ok(Outcome::Unknown(kinds.keys().next().map_or_else(|| NO_KIND.to_string(), String::clone))),
    }
}
