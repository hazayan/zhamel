use uefi::boot::{self, EventType, TimerTrigger, Tpl};
use uefi::system;

use crate::commands;
use crate::env::loader::LoaderEnv;
use uefi::Status;

pub fn fail_timeout_interrupt(env: &LoaderEnv, reason: &str) -> bool {
    let timeout = env
        .get("fail_timeout")
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(5);

    log::warn!("{} (fail_timeout={})", reason, timeout);

    if timeout == -2 {
        return true;
    }
    if timeout == -1 {
        return false;
    }
    if timeout == 0 {
        return poll_for_key();
    }
    wait_for_key_or_timeout(timeout as u64)
}

pub fn run_shell(env: &LoaderEnv) -> Option<Status> {
    let enabled = matches!(
        env.get("zhamel_interact"),
        Some("1") | Some("YES") | Some("yes") | Some("true")
    ) || env.get("zhamel_interact_cmds").is_some();
    if !enabled {
        return None;
    }
    log::info!("interactive: start");
    if let Some(cmds) = env.get("zhamel_interact_cmds") {
        for cmd in cmds.split(',').map(|c| c.trim()).filter(|c| !c.is_empty()) {
            log::info!("interactive: cmd {}", cmd);
            if let Some(status) = run_interactive_command(cmd, env) {
                return Some(status);
            }
        }
        return Some(Status::SUCCESS);
    }
    interactive_prompt(env)
}

fn interactive_prompt(env: &LoaderEnv) -> Option<Status> {
    let mut buf = alloc::string::String::new();
    loop {
        log::info!("interactive: ready");
        buf.clear();
        if !read_line(&mut buf) {
            return Some(Status::SUCCESS);
        }
        let cmd = buf.trim();
        if cmd.is_empty() {
            continue;
        }
        if let Some(status) = run_interactive_command(cmd, env) {
            return Some(status);
        }
    }
}

fn run_interactive_command(cmd: &str, env: &LoaderEnv) -> Option<Status> {
    match cmd {
        "exit" | "quit" => {
            log::info!("interactive: quit");
            Some(Status::SUCCESS)
        }
        "continue" | "boot" => {
            log::info!("interactive: continue");
            None
        }
        other => match commands::run_command(other, env) {
            Some(Status::SUCCESS) => None,
            Some(status) => Some(status),
            None => None,
        },
    }
}

fn read_line(out: &mut alloc::string::String) -> bool {
    let mut hit = false;
    system::with_stdin(|stdin| {
        let Some(key_event) = stdin.wait_for_key_event() else {
            return;
        };
        loop {
            let mut events = [unsafe { key_event.unsafe_clone() }];
            if boot::wait_for_event(&mut events).is_err() {
                return;
            }
            let Ok(Some(key)) = stdin.read_key() else {
                continue;
            };
            match key {
                uefi::proto::console::text::Key::Printable(ch) => {
                    let ch: char = ch.into();
                    match ch {
                        '\r' | '\n' => {
                            hit = true;
                            return;
                        }
                        '\u{8}' => {
                            out.pop();
                        }
                        _ => out.push(ch),
                    }
                }
                uefi::proto::console::text::Key::Special(_) => {}
            }
        }
    });
    hit
}

fn poll_for_key() -> bool {
    system::with_stdin(|stdin| match stdin.read_key() {
        Ok(Some(_)) => true,
        _ => false,
    })
}

fn wait_for_key_or_timeout(seconds: u64) -> bool {
    let mut hit = false;
    system::with_stdin(|stdin| {
        let Some(key_event) = stdin.wait_for_key_event() else {
            return;
        };
        let timer =
            match unsafe { boot::create_event(EventType::TIMER, Tpl::APPLICATION, None, None) } {
                Ok(timer) => timer,
                Err(_) => return,
            };
        let _ = boot::set_timer(&timer, TimerTrigger::Relative(seconds * 10_000_000));
        let timer_wait = unsafe { timer.unsafe_clone() };
        let mut events = [key_event, timer_wait];
        if let Ok(idx) = boot::wait_for_event(&mut events) {
            if idx == 0 {
                hit = true;
            }
        }
        let _ = boot::close_event(timer);
    });
    hit
}
