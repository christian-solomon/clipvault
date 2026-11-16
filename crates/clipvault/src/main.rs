//! ClipVault: clipboard history with an encrypted secrets vault, for X11.

mod app;
mod appearance;
mod assets;
mod hotkey;
mod locker;
mod tray;
mod ui;
mod x11;

use std::sync::{mpsc, Arc, Mutex};

use anyhow::Result;
use gpui::{App, AppContext, QuitMode};

use clipvault_core::clipboard::{ClipboardWriter, EchoGuard};
use clipvault_core::config::Config;
use clipvault_core::ephemeral::Ephemeral;
use clipvault_core::recorder::Recorder;
use clipvault_core::store::Store;
use clipvault_core::{harden, ipc, watcher};

use app::{AppEvent, AppState};

/// What a command line asked for. A second launch does not start a second
/// copy; it tells the running one what to do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Intent {
    /// Sit in the tray. What autostart wants.
    Daemon,
    /// Bring the window up.
    Ui,
    /// Show it, or hide it if it is already up.
    Toggle,
}

fn intent_of<S: AsRef<str>>(args: &[S]) -> Intent {
    for a in args {
        match a.as_ref() {
            "ui" | "--ui" => return Intent::Ui,
            "--toggle" | "-t" => return Intent::Toggle,
            _ => {}
        }
    }
    Intent::Daemon
}

const HELP: &str = "\
ClipVault - clipboard history with an encrypted secrets vault

USAGE:
    clipvault [COMMAND] [OPTIONS]

COMMANDS:
    (none)          Start in the system tray, or toggle the window if already
                    running. This is what an autostart entry should use.
    ui              Open the window, starting the app first if needed.

OPTIONS:
    -t, --toggle    Show the window, or hide it if it is already showing.
        --no-hotkey Do not grab the hotkey. Use this when the desktop's own
                    keyboard settings are bound to `clipvault ui` instead.
    -h, --help      Print this help.

ENVIRONMENT:
    CLIPVAULT_DATA_DIR                 database directory
                                       (default $XDG_DATA_HOME/dev.local.clipvault)
    CLIPVAULT_HOTKEY                   global hotkey, or `none` (default super+v)
    CLIPVAULT_AUTOLOCK_MINUTES         idle minutes before the vault locks (10)
    CLIPVAULT_CLIPBOARD_CLEAR_SECONDS  seconds before a copied secret is cleared,
                                       0 to never clear (30)
    CLIPVAULT_SENSITIVE_TTL_SECONDS    lifetime of memory-only credential clips (300)
    CLIPVAULT_HISTORY_MAX_ENTRIES      unpinned entries kept (500)
    CLIPVAULT_HISTORY_MAX_BYTES        byte budget for unpinned entries (268435456)
    CLIPVAULT_ALLOW_DEBUGGER=1         keep the process dumpable, for debugging
    RUST_LOG                           log filter, logs go to stdout
                                       (default warn,clipvault=info,clipvault_core=info)

Only one copy ever runs. Launching it again signals the running one.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        return;
    }
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn,clipvault=info,clipvault_core=info"),
    )
    .target(env_logger::Target::Stdout)
    .init();
    if let Err(e) = run(&args) {
        log::error!("{e:#}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<()> {
    let intent = intent_of(args);
    let cfg = Config::from_env()?;

    harden::private_umask();

    let command = match intent {
        Intent::Ui => ipc::Command::Show,
        Intent::Daemon | Intent::Toggle => ipc::Command::Toggle,
    };
    let primary = match ipc::claim(&ipc::default_dir(), command)? {
        ipc::Instance::Secondary => return Ok(()),
        ipc::Instance::Primary(p) => p,
    };

    // The portal answers method calls only while the process is dumpable.
    let dark = appearance::current();

    // Before the vault or any clipboard content can exist in this process.
    if cfg!(debug_assertions) || cfg.allow_debugger {
        log::warn!("process is dumpable (debug build or CLIPVAULT_ALLOW_DEBUGGER=1)");
    } else {
        harden::undumpable()?;
    }

    let mut store = Store::open(&cfg.db_path())?;
    store.set_limits(cfg.history_max_entries, cfg.history_max_bytes);
    log::info!("store: {}", cfg.db_path().display());
    let store = Arc::new(Mutex::new(store));
    let ephemeral = Arc::new(Mutex::new(Ephemeral::new(cfg.sensitive_ttl)));
    let guard = Arc::new(EchoGuard::default());

    let (tx, rx) = async_channel::unbounded::<AppEvent>();

    primary.serve({
        let tx = tx.clone();
        move |cmd| {
            let _ = tx.send_blocking(match cmd {
                ipc::Command::Show => AppEvent::Show,
                ipc::Command::Toggle => AppEvent::Toggle,
            });
        }
    })?;

    // Watcher (X thread) -> recorder (decode, detect, store) -> UI.
    let (captured_tx, captured_rx) = mpsc::channel();
    watcher::spawn(captured_tx);
    Recorder { store: store.clone(), ephemeral: ephemeral.clone(), guard: guard.clone() }.spawn(
        captured_rx,
        {
            let tx = tx.clone();
            move |r| {
                let _ = tx.send_blocking(AppEvent::Recorded(r));
            }
        },
    )?;

    let _tray = tray::spawn(tx.clone());
    let want_hotkey = !args.iter().any(|a| a == "--no-hotkey");
    let _hotkey = match (&cfg.hotkey, want_hotkey) {
        (Some(spec), true) => hotkey::register(spec, tx.clone()),
        _ => {
            log::info!("no global hotkey; expecting the desktop to bind `clipvault ui`");
            None
        }
    };
    locker::spawn(tx.clone());
    appearance::spawn(tx.clone());

    let clipboard = match ClipboardWriter::new(guard) {
        Ok(c) => Some(c),
        Err(e) => {
            log::error!("copying will not work: {e:#}");
            None
        }
    };

    gpui_platform::application()
        .with_assets(assets::Assets)
        .with_quit_mode(QuitMode::Explicit)
        .run(move |cx: &mut App| {
            gpui_component::init(cx);
            ui::bind_keys(cx);
            let state = cx.new(|cx| AppState::new(cfg, store, ephemeral, clipboard, dark, cx));
            let st = state.clone();
            cx.spawn(async move |cx| {
                while let Ok(event) = rx.recv().await {
                    cx.update(|cx| app::handle_event(&st, event, cx));
                }
            })
            .detach();
            if intent != Intent::Daemon {
                app::show_window(&state, cx);
            }
        });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{intent_of, Intent};

    #[test]
    fn no_arguments_means_sit_in_the_tray() {
        let none: [&str; 0] = [];
        assert_eq!(intent_of(&none), Intent::Daemon);
        assert_eq!(intent_of(&["--no-hotkey"]), Intent::Daemon);
    }

    #[test]
    fn ui_and_toggle_are_recognised() {
        assert_eq!(intent_of(&["ui"]), Intent::Ui);
        assert_eq!(intent_of(&["--ui"]), Intent::Ui);
        assert_eq!(intent_of(&["--toggle"]), Intent::Toggle);
        assert_eq!(intent_of(&["-t"]), Intent::Toggle);
    }

    #[test]
    fn a_command_is_found_among_other_flags() {
        assert_eq!(intent_of(&["--no-hotkey", "ui"]), Intent::Ui);
    }

    #[test]
    fn unknown_arguments_fall_back_to_the_daemon() {
        assert_eq!(intent_of(&["--what", "nonsense"]), Intent::Daemon);
    }
}
