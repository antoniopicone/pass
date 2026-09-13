//! GNOME Shell top-bar indicator (StatusNotifierItem, via the `ksni`
//! crate) that opens/focuses the main window. Left-clicking the icon or
//! choosing "Open Pass" from its menu both send [`TrayEvent::Open`];
//! "Quit" sends [`TrayEvent::Quit`] — both handled on the GTK main thread
//! (see `main.rs`'s `spawn_future_local` loop), since ksni's callbacks run
//! on its own background thread and GTK objects aren't `Send`.
//!
//! Known limitation: on stock/vanilla GNOME Shell this needs the
//! "AppIndicator and KStatusNotifierItem Support" extension to actually
//! show up in the top bar (GNOME dropped its own tray protocol years ago
//! and never implemented StatusNotifierItem natively) — Ubuntu ships that
//! extension by default, plain Fedora/Debian GNOME does not. Without it,
//! `spawn()` below still succeeds (or fails soft — see `main.rs`), the
//! icon just never becomes visible; the app remains fully usable by
//! launching it normally.

pub enum TrayEvent {
    Open,
    Quit,
}

pub struct AppTray {
    pub tx: async_channel::Sender<TrayEvent>,
}

impl AppTray {
    fn send(&self, event: TrayEvent) {
        // Unbounded channel, so this only fails if the receiving end (the
        // main window) has already gone away — nothing sensible to do
        // about that from here.
        let _ = self.tx.send_blocking(event);
    }
}

impl ksni::Tray for AppTray {
    fn id(&self) -> String {
        "it.antoniopicone.Pass".into()
    }

    fn title(&self) -> String {
        "Pass".into()
    }

    fn icon_name(&self) -> String {
        // A dedicated white-on-transparent silhouette (see
        // assets/icon-tray.svg), not the full-color app icon: a status
        // icon sitting in the panel alongside the clock/other indicators
        // reads better as a flat monochrome mark than a colored badge.
        "it.antoniopicone.Pass-tray".into()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(TrayEvent::Open);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        vec![
            ksni::menu::StandardItem {
                label: "Open Pass".into(),
                icon_name: "it.antoniopicone.Pass".into(),
                activate: Box::new(|this: &mut Self| this.send(TrayEvent::Open)),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            ksni::menu::StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit-symbolic".into(),
                activate: Box::new(|this: &mut Self| this.send(TrayEvent::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}
