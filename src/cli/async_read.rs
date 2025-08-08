// Code modified from https://github.com/acuteenvy/readpass/tree/71e200af0f363b7b0d433de9bcaf777538f17bbc
//
// This code is licensed under the "Apache License 2.0"
//
// My modifications are:
// - Changing reading from the terminal to be asynic using tokio.
// - Removing windows support.
// - Allow for reading input without hiding characters.

#[cfg(not(unix))]
compile_error!(
    r#"
    None unix system are not supported.
    This is due to not being able to hide asynchronous inputs for adding user passwords.
    If you know how to achieve this for other platforms open a PR and i'll add in support.
    "#
);

use libc::{ECHO, ECHONL, TCSANOW, c_int, tcgetattr, tcsetattr, termios};
use std::{mem::MaybeUninit, os::fd::AsRawFd};
use tokio::io::AsyncBufReadExt;
use tokio::{fs::File, io::BufReader};
use zeroize::Zeroizing;

const CTRL_U: char = 21 as char;

/// Asynchronously reads a password from an `(impl AsyncBufReadExt + Unpin)`.
///
/// This only reads the first line from the reader.
/// Newlines and carriage returns are trimmed from the end of the resulting [`String`].
async fn async_from_bufread(
    reader: &mut (impl AsyncBufReadExt + Unpin),
) -> std::io::Result<Zeroizing<String>> {
    let mut password = Zeroizing::new(String::new());

    // TODO: Make this stop on Ctrl + q
    // or any other appropriate input
    reader.read_line(&mut password).await?;

    let len = password.trim_end_matches(&['\r', '\n'][..]).len();
    password.truncate(len);

    // Ctrl-U should remove the line in terminals.
    password = match password.rfind(CTRL_U) {
        Some(last_ctrl_u_index) => Zeroizing::new(password[last_ctrl_u_index + 1..].to_string()),
        None => password,
    };

    Ok(password)
}

struct HiddenInput {
    fd: i32,
    term_orig: termios,
}

impl HiddenInput {
    fn new(fd: i32) -> std::io::Result<HiddenInput> {
        // Make two copies of the terminal settings. The first one will be modified
        // and the second one will act as a backup for when we want to set the
        // terminal back to its original state.
        let mut term_uninit = MaybeUninit::<termios>::uninit();
        io_result(unsafe { tcgetattr(fd, term_uninit.as_mut_ptr()) })?;
        let mut term = unsafe { term_uninit.assume_init() };
        let term_orig = term;

        // Hide the password. This is what makes this function useful.
        term.c_lflag &= !ECHO;

        // But don't hide the NL character when the user hits ENTER.
        term.c_lflag |= ECHONL;

        // Save the settings for now.
        io_result(unsafe { tcsetattr(fd, TCSANOW, &term) })?;

        Ok(HiddenInput { fd, term_orig })
    }
}

impl Drop for HiddenInput {
    fn drop(&mut self) {
        // Set the the mode back to normal.
        unsafe {
            tcsetattr(self.fd, TCSANOW, &self.term_orig);
        }
    }
}

/// Turns a C function return into an IO Result.
fn io_result(ret: c_int) -> std::io::Result<()> {
    match ret {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

/// Asynchronously reads a input from the TTY without echoing it back to the user.
///
/// Newlines and carriage returns are trimmed from the end of the resulting `String`.
///
/// # Errors
///
/// This function will return an I/O error if reading from `/dev/tty` fails.
pub async fn from_tty_hidden() -> std::io::Result<Zeroizing<String>> {
    let tty = File::open("/dev/tty").await?;
    let fd = tty.as_raw_fd();
    let mut reader = BufReader::new(tty);

    let _hidden_input = HiddenInput::new(fd)?;
    async_from_bufread(&mut reader).await
}

/// Asynchronously reads a input from the TTY.
///
/// Newlines and carriage returns are trimmed from the end of the resulting `String`.
///
/// # Errors
///
/// This function will return an I/O error if reading from `/dev/tty` fails.
pub async fn from_tty() -> std::io::Result<Zeroizing<String>> {
    let tty = File::open("/dev/tty").await?;
    let mut reader = BufReader::new(tty);

    async_from_bufread(&mut reader).await
}
