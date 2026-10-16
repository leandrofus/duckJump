use std::time::{Duration, Instant};
use duckjump_proto::gfx::Input;
use tracing::{debug, info, warn};

use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};

#[allow(dead_code)]
const USER_OVERRIDE_DURATION: Duration = Duration::from_secs(2);

/// Input injector with local user override priority.
#[allow(dead_code)]
pub struct InputController {
    enabled: bool,
    last_local_interaction: Option<Instant>,
    enigo: Option<Enigo>,
    prev_buttons: u8,
}

#[allow(dead_code)]
impl InputController {
    pub fn new() -> Self {
        let enigo = match Enigo::new(&Settings::default()) {
            Ok(e) => {
                info!("Enigo input simulator successfully initialized");
                Some(e)
            }
            Err(err) => {
                warn!("Failed to initialize Enigo input simulator: {:?}", err);
                None
            }
        };
        Self {
            enabled: false,
            last_local_interaction: None,
            enigo,
            prev_buttons: 0,
        }
    }

    /// Sets whether remote control input is authorized by the user.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if enabled {
            info!("Remote control input authorized by user");
        } else {
            info!("Remote control input disabled");
        }
    }

    /// Signals that the local user touched the keyboard or mouse.
    /// This immediately suspends remote operator inputs for 2 seconds.
    pub fn notify_local_user_activity(&mut self) {
        self.last_local_interaction = Some(Instant::now());
    }

    /// Reports whether the remote operator's input is currently accepted.
    pub fn is_operator_allowed(&self) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(last) = self.last_local_interaction {
            if last.elapsed() < USER_OVERRIDE_DURATION {
                debug!("Operator input suppressed due to local user priority override");
                return false;
            }
        }
        true
    }

    /// Processes an incoming DJTP input command from the operator.
    pub fn handle_remote_input(&mut self, input: Input) -> bool {
        if !self.is_operator_allowed() {
            return false;
        }

        match input {
            Input::Pointer { x, y, buttons } => {
                debug!(x, y, buttons, "Injecting pointer event");
                if let Some(ref mut enigo) = self.enigo {
                    let _ = enigo.move_mouse(x as i32, y as i32, Coordinate::Abs);

                    // Left button (bit 0)
                    if (buttons & 1) != (self.prev_buttons & 1) {
                        let dir = if (buttons & 1) != 0 { Direction::Press } else { Direction::Release };
                        let _ = enigo.button(Button::Left, dir);
                    }
                    // Middle button (bit 1)
                    if (buttons & 2) != (self.prev_buttons & 2) {
                        let dir = if (buttons & 2) != 0 { Direction::Press } else { Direction::Release };
                        let _ = enigo.button(Button::Middle, dir);
                    }
                    // Right button (bit 2)
                    if (buttons & 4) != (self.prev_buttons & 4) {
                        let dir = if (buttons & 4) != 0 { Direction::Press } else { Direction::Release };
                        let _ = enigo.button(Button::Right, dir);
                    }

                    // Mouse wheel (bit 3: wheel up, bit 4: wheel down)
                    if (buttons & 8) != 0 && (self.prev_buttons & 8) == 0 {
                        let _ = enigo.scroll(-1, Axis::Vertical);
                    }
                    if (buttons & 16) != 0 && (self.prev_buttons & 16) == 0 {
                        let _ = enigo.scroll(1, Axis::Vertical);
                    }

                    self.prev_buttons = buttons;
                }
                true
            }
            Input::Key { keysym, down, scancode } => {
                debug!(keysym, down, scancode, "Injecting key event");
                if let Some(ref mut enigo) = self.enigo {
                    let dir = if down { Direction::Press } else { Direction::Release };
                    if let Some(key) = keysym_to_enigo_key(keysym, scancode) {
                        let _ = enigo.key(key, dir);
                    } else if scancode != 0 {
                        let _ = enigo.raw(scancode, dir);
                    }
                }
                true
            }
            _ => {
                warn!("Unhandled input type");
                false
            }
        }
    }
}

fn keysym_to_enigo_key(keysym: u32, scancode: u16) -> Option<Key> {
    match keysym {
        0xff08 => Some(Key::Backspace),
        0xff09 => Some(Key::Tab),
        0xff0d | 0xff8d => Some(Key::Return),
        0xff1b => Some(Key::Escape),
        0xffff => Some(Key::Delete),
        0xff50 => Some(Key::Home),
        0xff51 => Some(Key::LeftArrow),
        0xff52 => Some(Key::UpArrow),
        0xff53 => Some(Key::RightArrow),
        0xff54 => Some(Key::DownArrow),
        0xff55 => Some(Key::PageUp),
        0xff56 => Some(Key::PageDown),
        0xff57 => Some(Key::End),
        0xffe1 | 0xffe2 => Some(Key::Shift),
        0xffe3 | 0xffe4 => Some(Key::Control),
        0xffe9 | 0xffea => Some(Key::Alt),
        0xffeb | 0xffec => Some(Key::Meta),
        0x20 => Some(Key::Space),
        0xffbe => Some(Key::F1),
        0xffbf => Some(Key::F2),
        0xffc0 => Some(Key::F3),
        0xffc1 => Some(Key::F4),
        0xffc2 => Some(Key::F5),
        0xffc3 => Some(Key::F6),
        0xffc4 => Some(Key::F7),
        0xffc5 => Some(Key::F8),
        0xffc6 => Some(Key::F9),
        0xffc7 => Some(Key::F10),
        0xffc8 => Some(Key::F11),
        0xffc9 => Some(Key::F12),
        ks if (0x21..=0x7e).contains(&ks) => {
            char::from_u32(ks).map(Key::Unicode)
        }
        ks if (0x01000000..=0x0110ffff).contains(&ks) => {
            char::from_u32(ks - 0x01000000).map(Key::Unicode)
        }
        ks if ks > 0 => Some(Key::Other(ks)),
        _ => {
            let _ = scancode;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_disabled_by_default() {
        let mut controller = InputController::new();
        let input = Input::Pointer { x: 100, y: 100, buttons: 0 };
        assert!(!controller.handle_remote_input(input));
    }

    #[test]
    fn test_local_user_priority_override() {
        let mut controller = InputController::new();
        controller.set_enabled(true);

        let input = Input::Pointer { x: 100, y: 100, buttons: 0 };
        assert!(controller.handle_remote_input(input));

        // User interacts locally: operator must be locked out
        controller.notify_local_user_activity();
        assert!(!controller.handle_remote_input(input));
    }
}
