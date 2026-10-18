//! The Janus desktop app for Windows and Linux: the screens of the mobile apps in egui, on the
//! same `janus-ffi` interface. `make desktop` runs it against the development mailbox.

mod app;
mod platform;
mod worker;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Janus")
            .with_inner_size([900.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Janus",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc.egui_ctx.clone())))),
    )
}
