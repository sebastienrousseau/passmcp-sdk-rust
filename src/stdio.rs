// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};

use serde::Deserialize;
use serde_json::Value;

use crate::client::Transport;
use crate::server::McpServer;
use crate::types::SdkError;

impl McpServer {
    /// Serves newline-delimited UTF-8 JSON-RPC 2.0 messages read from `reader`,
    /// writing single-line UTF-8 responses terminated by `\n` to `writer` and
    /// flushing after every response.
    ///
    /// Notifications emit no output line, and malformed lines emit `-32700 Parse error`
    /// while continuing until `reader` reaches EOF.
    pub fn serve_stdio<R: BufRead, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> io::Result<()> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                return Ok(());
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(resp) = self.handle_json(trimmed.as_bytes()) {
                writer.write_all(&resp)?;
                writer.write_all(b"\n")?;
                writer.flush()?;
            }
        }
    }
}

/// Client transport speaking newline-delimited UTF-8 JSON-RPC 2.0 over either
/// in-memory reader/writer streams or a spawned child process.
pub struct StdioTransport {
    reader: Box<dyn BufRead + Send>,
    writer: Option<Box<dyn Write + Send>>,
    child: Option<Child>,
}

impl StdioTransport {
    /// Wraps an arbitrary reader/writer stream pair for in-memory or piped testing.
    pub fn from_streams<R, W>(reader: R, writer: W) -> Self
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        Self {
            reader: Box::new(BufReader::new(reader)),
            writer: Some(Box::new(writer)),
            child: None,
        }
    }

    /// Spawns `program` with `args` attached over piped `stdin` and `stdout`
    /// (`stderr` inherited as null so diagnostics never pollute `stdout`).
    pub fn spawn<I, S>(program: &str, args: I) -> io::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing child stdin pipe"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing child stdout pipe"))?;
        Ok(Self {
            reader: Box::new(BufReader::new(stdout)),
            writer: Some(Box::new(stdin)),
            child: Some(child),
        })
    }

    /// Closes the outbound `stdin` stream so the server observes EOF and waits
    /// for any spawned child process to exit cleanly.
    pub fn close(&mut self) -> io::Result<()> {
        let _ = self.writer.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.wait()?;
        }
        Ok(())
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Transport for StdioTransport {
    fn send_json(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, SdkError> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| SdkError::Transport("stdio transport already closed".to_string()))?;
        let single_line = sanitize_single_line(payload);
        writer
            .write_all(&single_line)
            .and_then(|()| writer.write_all(b"\n"))
            .and_then(|()| writer.flush())
            .map_err(|e| SdkError::Transport(format!("stdio write: {e}")))?;

        if is_notification(payload) {
            return Ok(None);
        }
        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| SdkError::Transport(format!("stdio read: {e}")))?;
            if n == 0 {
                return Err(SdkError::Transport(
                    "unexpected EOF on stdio response stream".to_string(),
                ));
            }
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                return Ok(Some(trimmed.as_bytes().to_vec()));
            }
        }
    }
}

impl Transport for &mut StdioTransport {
    fn send_json(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, SdkError> {
        (**self).send_json(payload)
    }
}

fn sanitize_single_line(raw: &[u8]) -> Vec<u8> {
    raw.iter()
        .copied()
        .filter(|&b| b != b'\r')
        .map(|b| if b == b'\n' { b' ' } else { b })
        .collect()
}

fn is_notification(raw: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Peek {
        id: Option<Value>,
        #[serde(default)]
        method: String,
    }
    serde_json::from_slice::<Peek>(raw)
        .map(|p| !p.method.is_empty() && p.id.is_none())
        .unwrap_or(false)
}
