//! The screens of the mobile apps: contacts on the left; on the right an invitation, an answer,
//! the safety words, a chat or the networks.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};

use eframe::egui::{self, Align, Button, Color32, Id, Layout, RichText, TextEdit};
use janus_ffi::{Contact, Event, HistoryEntry, JanusError, NetworkInfo, read_network};

use crate::worker::{self, Command, Update};

const ROTATIONS: [(u8, &str); 4] = [
    (1, "Every hour"),
    (5, "Every 5 hours"),
    (10, "Every 10 hours"),
    (120, "Every 5 days"),
];

const MISMATCH: &str = "The words do not match. Check them and type them again. If they really \
                        differ, someone may be in the middle: cancel, and invite again in person.";

#[derive(Clone, PartialEq)]
enum View {
    Home,
    Invite,
    Answer,
    Confirm(String),
    Chat(String),
    Networks,
}

/// A's side of an invitation.
#[derive(Clone)]
enum Invitation {
    Waiting { words: String, network: String },
    Answered,
}

/// B's side of an invitation.
#[derive(Clone)]
enum Answer {
    Looking,
    Joined {
        contact: String,
        safety_words: String,
    },
}

pub struct App {
    commands: Sender<Command>,
    updates: Receiver<Update>,
    fatal: Option<String>,
    trouble: Option<String>,
    failure: Option<String>,
    contacts: Vec<Contact>,
    networks: Vec<NetworkInfo>,
    histories: HashMap<String, Vec<HistoryEntry>>,
    safety: HashMap<String, Option<String>>,
    unread: HashSet<String>,
    view: View,
    invitation: Option<Invitation>,
    answer: Option<Answer>,
    network: String,
    hours: u8,
    words: String,
    typed: String,
    name: String,
    draft: String,
    /// A message whose send has not come back yet, to restore if it fails.
    unsent: Option<String>,
    path: String,
    found: Option<(Vec<u8>, NetworkInfo)>,
    closing: Option<String>,
}

impl App {
    pub fn new(ctx: egui::Context) -> App {
        // Blocks screenshots and screen recording on Windows; X11 and Wayland cannot.
        ctx.send_viewport_cmd(egui::ViewportCommand::ContentProtected(true));
        let (commands, updates) = worker::spawn(ctx);
        App {
            commands,
            updates,
            fatal: None,
            trouble: None,
            failure: None,
            contacts: Vec::new(),
            networks: Vec::new(),
            histories: HashMap::new(),
            safety: HashMap::new(),
            unread: HashSet::new(),
            view: View::Home,
            invitation: None,
            answer: None,
            network: String::new(),
            hours: 10,
            words: String::new(),
            typed: String::new(),
            name: String::new(),
            draft: String::new(),
            unsent: None,
            path: String::new(),
            found: None,
            closing: None,
        }
    }

    fn send(&mut self, command: Command) {
        self.failure = None;
        // The worker only ends with the window.
        let _ = self.commands.send(command);
    }

    fn drain(&mut self) {
        while let Ok(update) = self.updates.try_recv() {
            match update {
                Update::Fatal(e) => self.fatal = Some(e),
                Update::Contacts(contacts) => self.contacts = contacts,
                Update::Networks(networks) => self.networks = networks,
                Update::History(contact, history) => {
                    self.unsent = None;
                    self.histories.insert(contact, history);
                }
                Update::Invited(words) => {
                    let network = self.network_name(&self.network);
                    self.invitation = Some(Invitation::Waiting { words, network });
                }
                Update::Verified(contact) => {
                    self.invitation = None;
                    self.typed.clear();
                    self.name.clear();
                    self.open_chat(contact);
                }
                Update::Joining => self.answer = Some(Answer::Looking),
                Update::Confirmed(contact) => {
                    self.answer = None;
                    self.words.clear();
                    self.name.clear();
                    self.open_chat(contact);
                }
                Update::SafetyWords(contact, words) => {
                    self.safety.insert(contact, words);
                }
                Update::Event(event) => self.event(event),
                Update::Failed(JanusError::Rejected)
                    if matches!(self.invitation, Some(Invitation::Answered)) =>
                {
                    self.failure = Some(MISMATCH.into());
                }
                Update::Failed(e) => {
                    if let Some(text) = self.unsent.take()
                        && self.draft.is_empty()
                    {
                        self.draft = text;
                    }
                    self.failure = Some(describe(&e));
                }
                Update::Trouble(trouble) => self.trouble = trouble,
            }
        }
    }

    fn event(&mut self, event: Event) {
        match event {
            Event::Answered => {
                if matches!(self.invitation, Some(Invitation::Waiting { .. })) {
                    self.invitation = Some(Invitation::Answered);
                }
            }
            Event::Joined {
                contact,
                safety_words,
            } => {
                self.answer = Some(Answer::Joined {
                    contact,
                    safety_words,
                });
            }
            Event::Message { contact, .. } => {
                if self.view != View::Chat(contact.clone()) {
                    self.unread.insert(contact);
                }
            }
            Event::Closed { contact } => {
                self.histories.remove(&contact);
                if self.view == View::Chat(contact) {
                    self.view = View::Home;
                }
            }
            Event::Dormant { .. } | Event::Awake { .. } => {}
        }
    }

    fn open_chat(&mut self, contact: String) {
        self.unread.remove(&contact);
        self.view = View::Chat(contact.clone());
        self.send(Command::History { contact });
    }

    fn network_name(&self, id: &str) -> String {
        self.networks
            .iter()
            .find(|n| n.id == id)
            .map(|n| n.name.clone())
            .unwrap_or_default()
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        for (text, view) in [
            ("Create an invitation", View::Invite),
            ("Answer an invitation", View::Answer),
            ("Networks", View::Networks),
        ] {
            if ui
                .add_sized([ui.available_width(), 28.0], Button::new(text))
                .clicked()
            {
                self.failure = None;
                self.view = view;
            }
        }
        ui.separator();
        if let Some(trouble) = &self.trouble {
            ui.colored_label(Color32::RED, trouble);
        }
        ui.label(
            RichText::new("The system keychain alone protects the storage key on this computer.")
                .small()
                .weak(),
        );
        if self.networks.is_empty() {
            ui.label("Install a network to start.");
        }
        if matches!(self.invitation, Some(Invitation::Answered))
            && ui
                .button("Your invitation was answered: type the safety words")
                .clicked()
        {
            self.view = View::Invite;
        }
        let waiting: Vec<Contact> = self
            .contacts
            .iter()
            .filter(|c| !c.confirmed)
            .cloned()
            .collect();
        let active: Vec<Contact> = (self.contacts.iter())
            .filter(|c| c.confirmed && !c.dormant)
            .cloned()
            .collect();
        let dormant: Vec<Contact> = (self.contacts.iter())
            .filter(|c| c.confirmed && c.dormant)
            .cloned()
            .collect();
        egui::ScrollArea::vertical().show(ui, |ui| {
            if !waiting.is_empty() {
                ui.add_space(8.0);
                ui.strong("Waiting for the safety words");
                for contact in waiting {
                    let view = View::Confirm(contact.id.clone());
                    if ui.selectable_label(self.view == view, "New contact").clicked() {
                        self.view = view;
                        self.send(Command::SafetyWords {
                            contact: contact.id,
                        });
                    }
                }
            }
            ui.add_space(8.0);
            ui.strong("Contacts");
            if active.is_empty() {
                ui.weak("No contacts yet. Create an invitation, or answer one.");
            }
            for contact in active.into_iter().chain(dormant.iter().cloned()) {
                if contact.dormant && dormant.first().is_some_and(|d| d.id == contact.id) {
                    ui.add_space(8.0);
                    ui.strong("Dormant");
                    ui.weak("Nothing heard for a year. Silence can be forged, so they stay until you close them.");
                }
                let label = if self.unread.contains(&contact.id) {
                    format!("● {}", contact.name)
                } else {
                    contact.name.clone()
                };
                let selected = self.view == View::Chat(contact.id.clone());
                if ui.selectable_label(selected, label).clicked() {
                    self.open_chat(contact.id);
                }
            }
        });
    }

    fn invite(&mut self, ui: &mut egui::Ui) {
        ui.heading("Invitation");
        match self.invitation.clone() {
            None => {
                self.network_picker(ui);
                ui.label("Key rotation");
                for (hours, label) in ROTATIONS {
                    ui.radio_value(&mut self.hours, hours, label);
                }
                ui.weak(
                    "The other person answers on the same network. Keys are replaced at least \
                     this often, even if nobody writes.",
                );
                let create = Button::new("Create the invitation");
                if ui.add_enabled(!self.network.is_empty(), create).clicked() {
                    self.send(Command::Invite {
                        network: self.network.clone(),
                        hours: self.hours,
                    });
                }
            }
            Some(Invitation::Waiting { words, network }) => {
                ui.label("Read these 6 words to the other person");
                ui.label(RichText::new(words).monospace().size(24.0));
                ui.weak(format!(
                    "In person or on a call, and tell them the network: {network}. They have 10 \
                     minutes to answer."
                ));
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Waiting for the answer…");
                });
                if ui.button("Cancel").clicked() {
                    self.invitation = None;
                }
            }
            Some(Invitation::Answered) => {
                ui.label("They answered. Ask them to read you the 3 words their screen shows.");
                field(ui, "3 safety words", &mut self.typed);
                field(ui, "Name for this contact", &mut self.name);
                ui.horizontal(|ui| {
                    let check = Button::new("Check the words");
                    if ui.add_enabled(!self.name.is_empty(), check).clicked() {
                        self.send(Command::Verify {
                            typed: words(&self.typed),
                            name: self.name.clone(),
                        });
                    }
                    if ui.button("Cancel").clicked() {
                        self.invitation = None;
                    }
                });
            }
        }
    }

    fn answer(&mut self, ui: &mut egui::Ui) {
        ui.heading("Answer");
        match self.answer.clone() {
            None => {
                self.network_picker(ui);
                ui.weak("The network the other person named; if they named none, the default.");
                field(ui, "6 words", &mut self.words);
                let answer = Button::new("Answer");
                if ui.add_enabled(!self.network.is_empty(), answer).clicked() {
                    self.send(Command::Join {
                        network: self.network.clone(),
                        words: words(&self.words),
                    });
                }
            }
            Some(Answer::Looking) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Looking for the invitation…");
                });
                ui.weak("An invitation lives 10 minutes.");
                if ui.button("Cancel").clicked() {
                    self.answer = None;
                }
            }
            Some(Answer::Joined {
                contact,
                safety_words,
            }) => self.confirm(ui, &contact, &safety_words),
        }
    }

    /// B: shows the safety words until the other person says they match.
    fn confirm(&mut self, ui: &mut egui::Ui, contact: &str, safety_words: &str) {
        ui.label("Read these 3 words to the other person");
        ui.label(RichText::new(safety_words).monospace().size(24.0));
        ui.weak("They type them and tell you whether they match. Nothing is sent before.");
        field(ui, "Name for this contact", &mut self.name);
        ui.horizontal(|ui| {
            let matched = Button::new("They say the words match");
            if ui.add_enabled(!self.name.is_empty(), matched).clicked() {
                self.send(Command::Confirm {
                    contact: contact.to_owned(),
                    name: self.name.clone(),
                });
            }
            if ui.button("They do not match").clicked() {
                self.send(Command::Close {
                    contact: contact.to_owned(),
                });
                self.answer = None;
                self.view = View::Home;
            }
        });
        ui.weak(
            "Words that do not match mean someone may be in the middle. Close this contact and \
             invite again in person.",
        );
    }

    fn chat(&mut self, ui: &mut egui::Ui, contact: &str) {
        let Some(info) = self.contacts.iter().find(|c| c.id == contact).cloned() else {
            ui.label("That contact no longer exists.");
            return;
        };
        ui.horizontal(|ui| {
            ui.heading(&info.name);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Close").clicked() {
                    self.closing = Some(contact.to_owned());
                }
            });
        });
        if info.dormant {
            ui.weak("Nothing heard from this contact for a year.");
        }
        egui::Panel::bottom("composer").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let edit = TextEdit::singleline(&mut self.draft)
                    .hint_text("Message")
                    .desired_width(ui.available_width() - 70.0);
                let edit = ui.add(edit);
                let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let ready = !self.draft.trim().is_empty();
                let clicked = ui.add_enabled(ready, Button::new("Send")).clicked();
                if ready && (enter || clicked) {
                    let text = std::mem::take(&mut self.draft).trim().to_owned();
                    self.unsent = Some(text.clone());
                    self.send(Command::Send {
                        contact: contact.to_owned(),
                        text,
                    });
                    edit.request_focus();
                }
            });
        });
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink(false)
            .show(ui, |ui| {
                for entry in self.histories.get(contact).into_iter().flatten() {
                    bubble(ui, entry);
                }
            });
    }

    fn networks(&mut self, ui: &mut egui::Ui) {
        ui.heading("Networks");
        ui.strong("Installed");
        if self.networks.is_empty() {
            ui.weak("None yet");
        }
        for network in &self.networks {
            ui.label(&network.name);
            ui.label(
                RichText::new(fingerprint(&network.id))
                    .monospace()
                    .small()
                    .weak(),
            );
        }
        ui.separator();
        ui.strong("Install a network");
        let label = ui.label("Drop the profile file on this window, or type its path:");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.path)
                .labelled_by(label.id);
            if ui.button("Read").clicked() {
                let path = PathBuf::from(self.path.trim());
                self.read_file(path);
            }
        });
        ui.weak("Only from a source you verified: a file from someone you trust.");
    }

    fn network_picker(&mut self, ui: &mut egui::Ui) {
        if !self.networks.iter().any(|n| n.id == self.network) {
            self.network = self
                .networks
                .first()
                .map(|n| n.id.clone())
                .unwrap_or_default();
        }
        egui::ComboBox::from_label("Network")
            .selected_text(self.network_name(&self.network))
            .show_ui(ui, |ui| {
                for network in &self.networks {
                    ui.selectable_value(&mut self.network, network.id.clone(), &network.name);
                }
            });
    }

    fn read_file(&mut self, path: PathBuf) {
        self.failure = None;
        match fs::read(&path) {
            Ok(profile) => match read_network(profile.clone()) {
                Ok(network) => self.found = Some((profile, network)),
                Err(e) => self.failure = Some(describe(&e)),
            },
            Err(e) => self.failure = Some(format!("{}: {e}", path.display())),
        }
    }

    /// The profile is shown before it is installed, since a substituted one would route the
    /// user through someone else's servers.
    fn install_dialog(&mut self, ctx: &egui::Context) {
        let Some((profile, network)) = self.found.clone() else {
            return;
        };
        let (mut install, mut cancel) = (false, false);
        egui::Modal::new(Id::unique("install")).show(ctx, |ui| {
            ui.heading(format!("Install {}?", network.name));
            ui.label("Check that this id matches your source:");
            ui.monospace(fingerprint(&network.id));
            ui.horizontal(|ui| {
                install = ui.button("Install").clicked();
                cancel = ui.button("Cancel").clicked();
            });
        });
        if install {
            self.send(Command::Install { profile });
        }
        if install || cancel {
            self.found = None;
            self.path.clear();
        }
    }

    fn close_dialog(&mut self, ctx: &egui::Context) {
        let Some(contact) = self.closing.clone() else {
            return;
        };
        let (mut close, mut cancel) = (false, false);
        egui::Modal::new(Id::unique("close")).show(ctx, |ui| {
            ui.heading("Close this conversation?");
            ui.label("Ends the session on both sides and deletes its history from this computer.");
            ui.horizontal(|ui| {
                close = ui.button("Close and delete").clicked();
                cancel = ui.button("Cancel").clicked();
            });
        });
        if close {
            self.send(Command::Close { contact });
            self.view = View::Home;
        }
        if close || cancel {
            self.closing = None;
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain();
        if let Some(fatal) = &self.fatal {
            egui::CentralPanel::default_margins().show(ui, |ui| {
                ui.heading("Janus could not start");
                ui.label(fatal.as_str());
            });
            return;
        }
        let dropped = ui.input(|i| i.raw.dropped_files.first().map(|f| f.path().to_owned()));
        if let Some(path) = dropped {
            self.view = View::Networks;
            self.read_file(path);
        }
        egui::Panel::left("contacts")
            .resizable(false)
            .exact_size(240.0)
            .show(ui, |ui| self.sidebar(ui));
        egui::CentralPanel::default_margins().show(ui, |ui| {
            match self.view.clone() {
                View::Home => {
                    ui.weak("Pick a contact, or create an invitation.");
                }
                View::Invite => self.invite(ui),
                View::Answer => self.answer(ui),
                View::Confirm(contact) => match self.safety.get(&contact).cloned() {
                    Some(Some(words)) => self.confirm(ui, &contact, &words),
                    Some(None) => {
                        ui.label("That contact no longer exists.");
                    }
                    None => {
                        ui.spinner();
                    }
                },
                View::Chat(contact) => self.chat(ui, &contact),
                View::Networks => self.networks(ui),
            }
            if let Some(failure) = &self.failure {
                ui.colored_label(Color32::RED, failure);
            }
        });
        let ctx = ui.ctx().clone();
        self.install_dialog(&ctx);
        self.close_dialog(&ctx);
    }
}

/// A text field with a label that screen readers announce with it.
fn field(ui: &mut egui::Ui, label: &str, text: &mut String) {
    let label = ui.label(label);
    ui.text_edit_singleline(text).labelled_by(label.id);
}

fn bubble(ui: &mut egui::Ui, entry: &HistoryEntry) {
    let text = String::from_utf8(entry.data.clone())
        .unwrap_or_else(|_| format!("[{} bytes]", entry.data.len()));
    let (layout, fill) = if entry.mine {
        (
            Layout::right_to_left(Align::TOP),
            ui.visuals().selection.bg_fill,
        )
    } else {
        (
            Layout::left_to_right(Align::TOP),
            ui.visuals().faint_bg_color,
        )
    };
    ui.with_layout(layout, |ui| {
        let width = ui.available_width() * 0.7;
        egui::Frame::new()
            .fill(fill)
            .corner_radius(8.0)
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.set_max_width(width);
                ui.label(text);
            });
    });
}

fn describe(e: &JanusError) -> String {
    match e {
        JanusError::BadWords => "Exactly 6 words from the list are needed.".into(),
        JanusError::Expired => "The invitation expired. Start a new one.".into(),
        JanusError::Rejected => "The words do not match.".into(),
        JanusError::NotConfirmed => "The safety words are not confirmed yet.".into(),
        JanusError::TooLarge => "The message is over 16 MB.".into(),
        JanusError::UnknownNetwork => "That network is not installed.".into(),
        JanusError::BadProfile => "This is not a network profile.".into(),
        JanusError::UnknownContact => "That contact no longer exists.".into(),
        JanusError::BadInterval => "Pick one of the offered intervals.".into(),
        JanusError::BadKey => "The storage key is damaged.".into(),
        JanusError::Storage { reason } => format!("Storage failed: {reason}"),
    }
}

/// The network id in groups of 4 hex digits, for people to compare.
fn fingerprint(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    chars
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Words as the core expects them: lowercase, single spaces.
fn words(typed: &str) -> String {
    typed
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_words_and_ids_are_normalized() {
        assert_eq!(words("  Glue  NORTH\tcook "), "glue north cook");
        assert_eq!(fingerprint("0123456789"), "0123 4567 89");
    }
}
