//! Release-bound artifacts: built from this repository, served read-only
//! (port of `artifacts.py`, plus the request/response logic of
//! `GET /artifacts/{id}[/{version}]` from `server.py`).
//!
//! **Single source of truth: the git commit.** Artifacts are never
//! uploaded. [`build`] packages fixed repository paths ([`SOURCES`]) into a
//! directory with a `manifest.json` that records the commit, the release
//! version, and each file's SHA-256. The image build runs it once; the
//! release job copies those exact files out of the published image instead
//! of rebuilding them (gzip output depends on the zlib build), so there is
//! exactly one build of every artifact.
//!
//! The running server reads that directory read-only ([`ArtifactStore`]).
//! Every file's SHA-256 is verified against the manifest at load; a
//! mismatching file is disabled, never served. [`ArtifactStore::stream`] is
//! the only way bytes leave the store -- the authenticated HTTP download and
//! the `artifact.transfer` tool both use it.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::pathutil;
use crate::pyfmt::{os_error, repr_value};

pub const MANIFEST: &str = "manifest.json";
pub const SCHEMA: i64 = 1;
pub const DEFAULT_DIR: &str = "/opt/gatekeeper/artifacts";
pub const ID_PATTERN: &str = r"^[a-z0-9][a-z0-9-]{0,62}$";
/// A version is the full commit id or an unambiguous prefix of it.
pub const VERSION_PATTERN: &str = r"^[0-9a-f]{7,40}$";
pub const CHUNK: usize = 64 * 1024;

/// `ID_RE`.
pub fn id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(ID_PATTERN).expect("ID_RE"))
}

/// `VERSION_RE`.
pub fn version_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(VERSION_PATTERN).expect("VERSION_RE"))
}

/// Python's `re.fullmatch` with a `^...$` pattern: `$` also matches before
/// a trailing newline in Python, but `fullmatch` requires the whole string,
/// so a trailing newline never matches. The `regex` crate's `$` is
/// end-of-text, which is the same thing here.
fn fullmatch(re: &Regex, s: &str) -> bool {
    re.is_match(s)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// A single file.
    File,
    /// A directory packaged as a deterministic tar.gz.
    Tree,
}

/// One entry of `SOURCES`: what gets built, from where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub id: String,
    pub kind: SourceKind,
    pub path: String,
    pub file: String,
    pub media_type: String,
    pub text: bool,
}

/// What gets built, from where. Fixed here, not configurable: an artifact
/// is a repository path at a commit, nothing else. Empty since 0.52.0: the
/// Hermes recovery adapter and its contract, the only artifacts so far,
/// were removed with the recovery supervisor. The image still carries a
/// commit-bound (empty) manifest.
pub const SOURCES: &[Source] = &[];

const EXCLUDE_PARTS: &[&[u8]] = &[b"__pycache__", b".pytest_cache", b"out"];

// -- Build -----------------------------------------------------------------

/// `os.walk(base)` with `followlinks=False`, sorted and filtered as
/// `_deterministic_tar` does; returns the relative paths of the files.
fn walk(dir: &Path, rel: &[u8], out: &mut Vec<Vec<u8>>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return; // os.walk's default onerror: skip silently
    };
    let mut dirnames: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut filenames: Vec<Vec<u8>> = Vec::new();
    for entry in read.flatten() {
        let name = entry.file_name().as_bytes().to_vec();
        let path = entry.path();
        // DirEntry.is_dir() follows symlinks, like os.scandir's.
        let is_dir = std::fs::metadata(&path).map(|m| m.is_dir()).unwrap_or(false);
        if is_dir {
            let is_link = entry.file_type().map(|t| t.is_symlink()).unwrap_or(false);
            dirnames.push((name, is_link));
        } else {
            filenames.push(name);
        }
    }
    dirnames.retain(|(d, _)| !EXCLUDE_PARTS.contains(&d.as_slice()));
    dirnames.sort();
    filenames.sort();
    let join = |name: &[u8]| -> Vec<u8> {
        if rel.is_empty() {
            name.to_vec()
        } else {
            let mut v = rel.to_vec();
            v.push(b'/');
            v.extend_from_slice(name);
            v
        }
    };
    for name in filenames {
        if name.ends_with(b".pyc") {
            continue;
        }
        out.push(join(&name));
    }
    for (name, is_link) in dirnames {
        if is_link {
            continue; // followlinks=False: listed, never descended into
        }
        walk(&dir.join(std::ffi::OsStr::from_bytes(&name)), &join(&name), out);
    }
}

/// Python's view of a filesystem name decoded with `surrogateescape`: the
/// character count, whether it is pure ASCII, whether it holds undecodable
/// bytes, and its `encode("ascii", "replace")` form.
struct PyName {
    chars: usize,
    ascii: bool,
    binary: bool,
    ascii_replaced: Vec<u8>,
}

fn py_name(bytes: &[u8]) -> PyName {
    let mut name = PyName { chars: 0, ascii: true, binary: false, ascii_replaced: Vec::new() };
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            name.chars += 1;
            if c.is_ascii() {
                name.ascii_replaced.push(c as u8);
            } else {
                name.ascii = false;
                name.ascii_replaced.push(b'?');
            }
        }
        for _ in chunk.invalid() {
            name.chars += 1;
            name.ascii = false;
            name.binary = true;
            name.ascii_replaced.push(b'?');
        }
    }
    name
}

const BLOCKSIZE: usize = 512;
const RECORDSIZE: usize = 20 * BLOCKSIZE;
const POSIX_MAGIC: &[u8] = b"ustar\x0000";

/// tarfile's `stn`: truncate and NUL-pad.
fn stn(out: &mut Vec<u8>, s: &[u8], length: usize) {
    let s = &s[..s.len().min(length)];
    out.extend_from_slice(s);
    out.resize(out.len() + (length - s.len()), 0);
}

/// tarfile's `itn` for the ustar format (callers keep `n` in range).
fn itn(out: &mut Vec<u8>, n: u64, digits: usize) {
    out.extend_from_slice(format!("{:0width$o}", n, width = digits - 1).as_bytes());
    out.push(0);
}

/// tarfile's `_create_header` for a ustar block.
fn ustar_header(name: &[u8], mode: u64, size: u64, typeflag: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(BLOCKSIZE);
    stn(&mut buf, name, 100);
    itn(&mut buf, mode & 0o7777, 8);
    itn(&mut buf, 0, 8); // uid
    itn(&mut buf, 0, 8); // gid
    itn(&mut buf, size, 12);
    itn(&mut buf, 0, 12); // mtime
    buf.extend_from_slice(b"        "); // checksum field
    buf.push(typeflag);
    stn(&mut buf, b"", 100); // linkname
    buf.extend_from_slice(POSIX_MAGIC);
    stn(&mut buf, b"", 32); // uname
    stn(&mut buf, b"", 32); // gname
    stn(&mut buf, b"", 8); // devmajor
    stn(&mut buf, b"", 8); // devminor
    stn(&mut buf, b"", 155); // prefix
    buf.resize(BLOCKSIZE, 0);
    let chksum: u32 = buf.iter().map(|&b| b as u32).sum();
    let field = format!("{:06o}\0", chksum);
    buf[148..155].copy_from_slice(field.as_bytes());
    buf
}

fn pad_block(out: &mut Vec<u8>) {
    let rem = out.len() % BLOCKSIZE;
    if rem != 0 {
        out.resize(out.len() + BLOCKSIZE - rem, 0);
    }
}

/// tarfile's `_create_pax_generic_header` (type `x`).
fn pax_header(records: &[(&str, Vec<u8>)], binary: bool) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    if binary {
        payload.extend_from_slice(b"21 hdrcharset=BINARY\n");
    }
    for (keyword, value) in records {
        let l = keyword.len() + value.len() + 3;
        let mut p = 0usize;
        loop {
            let n = l + p.to_string().len();
            if n == p {
                break;
            }
            p = n;
        }
        payload.extend_from_slice(p.to_string().as_bytes());
        payload.push(b' ');
        payload.extend_from_slice(keyword.as_bytes());
        payload.push(b'=');
        payload.extend_from_slice(value);
        payload.push(b'\n');
    }
    let mut out = ustar_header(b"././@PaxHeader", 0, payload.len() as u64, b'x');
    out.extend_from_slice(&payload);
    pad_block(&mut out);
    out
}

/// One regular-file member as `tarfile.TarInfo.tobuf(PAX_FORMAT)` writes
/// it, with mtime 0, uid/gid 0, empty uname/gname and mode 0644.
fn tar_member(out: &mut Vec<u8>, name: &[u8], data: &[u8]) {
    let info = py_name(name);
    let mut records: Vec<(&str, Vec<u8>)> = Vec::new();
    if !info.ascii || info.chars > 100 {
        records.push(("path", name.to_vec()));
    }
    let mut size = data.len() as u64;
    if size >= 8u64.pow(11) {
        records.push(("size", size.to_string().into_bytes()));
        size = 0;
    }
    if !records.is_empty() {
        // Only the path can carry undecodable bytes.
        out.extend_from_slice(&pax_header(&records, info.binary));
    }
    out.extend_from_slice(&ustar_header(&info.ascii_replaced, 0o644, size, b'0'));
    out.extend_from_slice(data);
    pad_block(out);
}

/// The uncompressed tar of `_deterministic_tar`.
fn deterministic_tar_raw(root: &str, rel: &str, prefix: &str) -> std::io::Result<Vec<u8>> {
    let base = pathutil::join(root, rel);
    let mut entries: Vec<Vec<u8>> = Vec::new();
    walk(Path::new(&base), b"", &mut entries);
    // PORT NOTE: Python sorts the decoded names by code point; for valid
    // UTF-8 that is byte order. Names with undecodable bytes (surrogate
    // escapes in Python) may sort differently.
    entries.sort();
    let mut raw: Vec<u8> = Vec::new();
    for relpath in entries {
        let full = Path::new(&base).join(std::ffi::OsStr::from_bytes(&relpath));
        let mut data = std::fs::read(&full)?;
        let textual = [&b".py"[..], b".md", b".yaml", b".json", b".txt"].iter().any(|s| relpath.ends_with(s))
            || !relpath.contains(&b'.');
        if textual {
            // Checkout line endings never change the hash.
            data = replace_crlf(&data);
        }
        let mut name = prefix.as_bytes().to_vec();
        name.push(b'/');
        name.extend_from_slice(&relpath);
        tar_member(&mut raw, &name, &data);
    }
    // TarFile.close(): two zero blocks, then pad to a full record.
    raw.resize(raw.len() + 2 * BLOCKSIZE, 0);
    let rem = raw.len() % RECORDSIZE;
    if rem != 0 {
        raw.resize(raw.len() + RECORDSIZE - rem, 0);
    }
    Ok(raw)
}

/// `GzipFile(filename="", mode="wb", mtime=0)` with the default
/// compresslevel 9: no name, mtime 0, XFL 2, OS 255.
fn gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut out = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x02, 0xff];
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(9));
    enc.write_all(data)?;
    out.extend_from_slice(&enc.finish()?);
    let mut crc = flate2::Crc::new();
    crc.update(data);
    out.extend_from_slice(&crc.sum().to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    Ok(out)
}

/// A byte-identical tar.gz for identical input: sorted entries, fixed
/// mtime/owner/mode, gzip header without timestamp or name.
pub fn deterministic_tar(root: &str, rel: &str, prefix: &str) -> std::io::Result<Vec<u8>> {
    gzip(&deterministic_tar_raw(root, rel, prefix)?)
}

fn replace_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\r' && data.get(i + 1) == Some(&b'\n') {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

/// Build every artifact in `sources` (Python's default: [`SOURCES`]) from
/// the checkout at `root` into `out`. Returns the manifest.
pub fn build(root: &str, out: &str, commit: &str, release: &str, sources: &[Source]) -> std::io::Result<Value> {
    std::fs::create_dir_all(out)?;
    let mut artifacts = Vec::new();
    for src in sources {
        let data = match src.kind {
            SourceKind::File => replace_crlf(&std::fs::read(pathutil::join(root, &src.path))?),
            SourceKind::Tree => deterministic_tar(root, &src.path, &src.id)?,
        };
        std::fs::write(pathutil::join(out, &src.file), &data)?;
        artifacts.push(json!({
            "id": src.id, "version": commit, "file": src.file,
            "media_type": src.media_type, "text": src.text, "size": data.len(),
            "sha256": hex::encode(Sha256::digest(&data)), "source": src.path,
        }));
    }
    let manifest = json!({"schema": SCHEMA, "release": release, "commit": commit, "artifacts": artifacts});
    let text = crate::pyjson::dumps_with(&manifest, &crate::pyjson::Opts::indented(2).sorted());
    std::fs::write(pathutil::join(out, MANIFEST), format!("{text}\n"))?;
    Ok(manifest)
}

// -- Store -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub id: String,
    pub version: String,
    pub file: String,
    pub media_type: String,
    pub text: bool,
    pub size: u64,
    pub sha256: String,
    pub source: String,
    pub commit: String,
    pub release: String,
}

impl Artifact {
    pub fn download_path(&self) -> String {
        format!("/artifacts/{}/{}", self.id, self.version)
    }

    pub fn public(&self) -> Value {
        json!({"id": self.id, "version": self.version, "commit": self.commit,
               "release": self.release, "file": self.file, "media_type": self.media_type,
               "size": self.size, "sha256": self.sha256, "source": self.source,
               "download_path": self.download_path()})
    }
}

/// The bytes on disk are not the bytes the manifest describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityError(pub String);

impl fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IntegrityError {}

/// An error while streaming: an `OSError` or an [`IntegrityError`].
#[derive(Debug)]
pub enum StreamError {
    Io { error: std::io::Error, path: String },
    Integrity(IntegrityError),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Io { error, path } => f.write_str(&os_error(error, path)),
            StreamError::Integrity(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for StreamError {}

/// What `read_text` can raise: a `ValueError` (not text, too large, not
/// UTF-8), an [`IntegrityError`], or an `OSError`.
#[derive(Debug)]
pub enum ReadTextError {
    Value(String),
    Stream(StreamError),
}

impl ReadTextError {
    /// `except (ValueError, IntegrityError)` in `execute_artifact.py`.
    pub fn is_value_or_integrity(&self) -> bool {
        !matches!(self, ReadTextError::Stream(StreamError::Io { .. }))
    }
}

impl fmt::Display for ReadTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadTextError::Value(m) => f.write_str(m),
            ReadTextError::Stream(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ReadTextError {}

/// Python's `str(UnicodeDecodeError)` for `bytes.decode("utf-8")`.
fn utf8_error_text(data: &[u8], err: &std::str::Utf8Error) -> String {
    let pos = err.valid_up_to();
    match err.error_len() {
        Some(_) => {
            let b = data[pos];
            let reason = if (0x80..=0xbf).contains(&b) || b == 0xc0 || b == 0xc1 || b >= 0xf5 {
                "invalid start byte"
            } else {
                "invalid continuation byte"
            };
            format!("'utf-8' codec can't decode byte 0x{b:02x} in position {pos}: {reason}")
        }
        None => {
            let end = data.len() - 1;
            if end == pos {
                format!("'utf-8' codec can't decode byte 0x{:02x} in position {pos}: unexpected end of data", data[pos])
            } else {
                format!("'utf-8' codec can't decode bytes in position {pos}-{end}: unexpected end of data")
            }
        }
    }
}

/// The verified bytes of one artifact, in chunks of [`CHUNK`]. Yields an
/// `Err` (once, at the end) if what was read is not what the manifest
/// promises; callers must not commit anything before the iterator is
/// exhausted. Opening is lazy, like Python's generator: an unreadable file
/// is an `Err` on the first `next()`.
pub struct ArtifactStream {
    path: String,
    art: Artifact,
    file: Option<File>,
    digest: Sha256,
    size: u64,
    done: bool,
}

impl Iterator for ArtifactStream {
    type Item = Result<Vec<u8>, StreamError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.file.is_none() {
            match File::open(&self.path) {
                Ok(f) => self.file = Some(f),
                Err(error) => {
                    self.done = true;
                    return Some(Err(StreamError::Io { error, path: self.path.clone() }));
                }
            }
        }
        let file = self.file.as_mut().unwrap();
        let mut buf = vec![0u8; CHUNK];
        let mut filled = 0;
        // f.read(CHUNK) on a regular file returns CHUNK bytes until EOF.
        while filled < CHUNK {
            match file.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.done = true;
                    return Some(Err(StreamError::Io { error, path: String::new() }));
                }
            }
        }
        if filled > 0 {
            buf.truncate(filled);
            self.digest.update(&buf);
            self.size += filled as u64;
            return Some(Ok(buf));
        }
        self.done = true;
        self.file = None;
        let actual = hex::encode(std::mem::take(&mut self.digest).finalize());
        if actual != self.art.sha256 || self.size != self.art.size {
            return Some(Err(StreamError::Integrity(IntegrityError(format!(
                "{}: content changed since startup",
                self.art.id
            )))));
        }
        None
    }
}

/// Read-only view of one build's artifact directory.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    pub directory: String,
    pub commit: String,
    pub release: String,
    artifacts: HashMap<String, Artifact>,
    /// Artifact id -> why it is not served.
    pub disabled: BTreeMap<String, String>,
}

fn sha256_file(path: &str) -> std::io::Result<String> {
    let mut f = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn truthy_str(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) if n.as_f64() == Some(0.0) => String::new(),
        Some(Value::Array(a)) if a.is_empty() => String::new(),
        Some(Value::Object(m)) if m.is_empty() => String::new(),
        Some(other) => crate::pyfmt::str_value(other),
    }
}

/// `manifest.get("schema") == 1` with Python's equality (`1 == 1.0 == True`).
fn schema_matches(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Number(n)) => n.as_f64() == Some(SCHEMA as f64),
        Some(Value::Bool(b)) => *b,
        _ => false,
    }
}

fn parse_entry(entry: &Map<String, Value>, commit: &str, release: &str) -> Option<Artifact> {
    let s = |k: &str| entry.get(k).and_then(Value::as_str).map(str::to_string);
    Some(Artifact {
        id: s("id")?,
        version: s("version")?,
        file: s("file")?,
        media_type: s("media_type")?,
        text: entry.get("text")?.as_bool()?,
        size: entry.get("size")?.as_u64()?,
        sha256: s("sha256")?,
        source: s("source")?,
        commit: commit.to_string(),
        release: release.to_string(),
    })
}

impl ArtifactStore {
    pub fn new(directory: impl Into<String>) -> Self {
        let mut store = ArtifactStore {
            directory: directory.into(),
            commit: String::new(),
            release: String::new(),
            artifacts: HashMap::new(),
            disabled: BTreeMap::new(),
        };
        store.load();
        store
    }

    /// `GATEKEEPER_ARTIFACT_DIR`, else [`DEFAULT_DIR`].
    pub fn from_env() -> Self {
        Self::new(std::env::var("GATEKEEPER_ARTIFACT_DIR").unwrap_or_else(|_| DEFAULT_DIR.to_string()))
    }

    fn load(&mut self) {
        let path = pathutil::join(&self.directory, MANIFEST);
        let manifest: Value = match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return, // nothing is served
            Err(e) => {
                tracing::warn!(
                    "Artifact manifest {} is unreadable ({}); no artifacts are served.",
                    path,
                    os_error(&e, &path)
                );
                return;
            }
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("Artifact manifest {} is unreadable ({}); no artifacts are served.", path, e);
                    return;
                }
            },
        };
        // PORT NOTE: a manifest whose top level is not an object crashed the
        // Python store (AttributeError); here it reads as an unknown schema.
        let empty = Map::new();
        let obj = manifest.as_object().unwrap_or(&empty);
        if !schema_matches(obj.get("schema")) {
            let schema = repr_value(obj.get("schema").unwrap_or(&Value::Null));
            tracing::warn!("Artifact manifest {} has unknown schema {}; no artifacts are served.", path, schema);
            return;
        }
        self.commit = truthy_str(obj.get("commit"));
        self.release = truthy_str(obj.get("release"));
        let entries = match obj.get("artifacts") {
            Some(Value::Array(items)) => items.clone(),
            _ => Vec::new(),
        };
        for entry in entries {
            let art = entry.as_object().and_then(|m| parse_entry(m, &self.commit, &self.release));
            let Some(art) = art else {
                // PORT NOTE: Python raised KeyError/TypeError on a malformed
                // entry and the whole store failed to load; here only that
                // entry is disabled.
                let id = entry.get("id").map(crate::pyfmt::str_value).unwrap_or_default();
                self.disabled.insert(id, "invalid manifest entry".into());
                continue;
            };
            if !fullmatch(id_re(), &art.id) || pathutil::basename(&art.file) != art.file {
                self.disabled.insert(art.id.clone(), "invalid manifest entry".into());
                continue;
            }
            let file_path = pathutil::join(&self.directory, &art.file);
            let actual = match sha256_file(&file_path) {
                Ok(a) => a,
                Err(e) => {
                    self.disabled.insert(art.id.clone(), format!("unreadable: {}", os_error(&e, &file_path)));
                    continue;
                }
            };
            if actual != art.sha256 {
                self.disabled.insert(art.id.clone(), "sha256 mismatch".into());
                tracing::warn!(
                    "Artifact {} ({}) does not match its manifest sha256; it is disabled.",
                    art.id,
                    art.file
                );
                continue;
            }
            self.artifacts.insert(art.id.clone(), art);
        }
    }

    /// Every served artifact, sorted by id.
    pub fn list(&self) -> Vec<&Artifact> {
        let mut items: Vec<&Artifact> = self.artifacts.values().collect();
        items.sort_by(|a, b| a.id.cmp(&b.id));
        items
    }

    /// The artifact `artifact_id`, if served and -- when `version` is given
    /// and non-empty -- `version` is a valid prefix of its commit.
    pub fn get(&self, artifact_id: &str, version: Option<&str>) -> Option<&Artifact> {
        let art = self.artifacts.get(artifact_id)?;
        if let Some(version) = version.filter(|v| !v.is_empty()) {
            if !(fullmatch(version_re(), version) && art.version.starts_with(version)) {
                return None;
            }
        }
        Some(art)
    }

    /// The bytes of `art`, verified (see [`ArtifactStream`]).
    pub fn stream(&self, art: &Artifact) -> ArtifactStream {
        ArtifactStream {
            path: pathutil::join(&self.directory, &art.file),
            art: art.clone(),
            file: None,
            digest: Sha256::new(),
            size: 0,
            done: false,
        }
    }

    pub fn read_text(&self, art: &Artifact, max_bytes: u64) -> Result<String, ReadTextError> {
        if !art.text {
            return Err(ReadTextError::Value("not a text artifact".into()));
        }
        if art.size > max_bytes {
            return Err(ReadTextError::Value(format!(
                "{} bytes exceed the output limit of {max_bytes}",
                art.size
            )));
        }
        let mut data = Vec::new();
        for chunk in self.stream(art) {
            data.extend_from_slice(&chunk.map_err(ReadTextError::Stream)?);
        }
        String::from_utf8(data).map_err(|e| {
            let text = utf8_error_text(e.as_bytes(), &e.utf8_error());
            ReadTextError::Value(text)
        })
    }
}

// -- CLI (`python -m gatekeeper.artifacts`) ----------------------------------

const CLI_OPTIONS: [&str; 5] = ["--help", "--root", "--out", "--commit", "--release"];

fn usage(prog: &str) -> String {
    format!("usage: {prog} [-h] [--root ROOT] --out OUT --commit COMMIT --release RELEASE")
}

fn cli_error(prog: &str, message: &str) -> i32 {
    eprintln!("{}\n{prog}: error: {message}", usage(prog));
    2
}

/// Resolves `--opt` or an unambiguous prefix of it, like argparse.
fn resolve_option(given: &str) -> Result<&'static str, String> {
    if let Some(exact) = CLI_OPTIONS.iter().find(|o| **o == given) {
        return Ok(exact);
    }
    let matches: Vec<&'static str> = CLI_OPTIONS.iter().copied().filter(|o| o.starts_with(given)).collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(format!("unrecognized arguments: {given}")),
        _ => Err(format!("ambiguous option: {given} could match {}", matches.join(", "))),
    }
}

/// The build CLI (`python -m gatekeeper.artifacts`): `--root` (default
/// `.`), `--out`, `--commit` and `--release` (required). `prog` is the
/// program name in usage text. Returns the exit code.
// PORT NOTE: a small argparse subset (exact or prefix options, `--opt=v`),
// enough for the Dockerfile's invocation; messages follow argparse.
pub fn main(prog: &str, argv: &[String]) -> i32 {
    let mut values: HashMap<&'static str, String> = HashMap::new();
    let mut unknown: Vec<String> = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        i += 1;
        if arg == "-h" {
            values.insert("--help", String::new());
            break;
        }
        if !(arg.starts_with("--") && arg.len() > 2) {
            unknown.push(arg.clone());
            continue;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (arg.as_str(), None),
        };
        let option = match resolve_option(name) {
            Ok(o) => o,
            Err(message) => return cli_error(prog, &message),
        };
        if option == "--help" {
            values.insert("--help", String::new());
            break;
        }
        let value = match inline {
            Some(v) => v,
            None => match argv.get(i).filter(|v| !(v.starts_with('-') && v.len() > 1)) {
                Some(v) => {
                    i += 1;
                    v.clone()
                }
                None => return cli_error(prog, &format!("argument {option}: expected one argument")),
            },
        };
        values.insert(option, value);
    }
    if values.contains_key("--help") {
        println!(
            "{}\n\nBuild the release-bound artifact directory.\n\noptions:\n  \
             -h, --help         show this help message and exit\n  \
             --root ROOT        repository checkout\n  --out OUT\n  --commit COMMIT\n  --release RELEASE",
            usage(prog)
        );
        return 0;
    }
    let missing: Vec<&str> =
        ["--out", "--commit", "--release"].into_iter().filter(|o| !values.contains_key(o)).collect();
    if !missing.is_empty() {
        return cli_error(prog, &format!("the following arguments are required: {}", missing.join(", ")));
    }
    if !unknown.is_empty() {
        return cli_error(prog, &format!("unrecognized arguments: {}", unknown.join(" ")));
    }
    let root = values.get("--root").cloned().unwrap_or_else(|| ".".into());
    let manifest = match build(&root, &values["--out"], &values["--commit"], &values["--release"], SOURCES) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{prog}: {e}");
            return 1;
        }
    };
    for a in manifest["artifacts"].as_array().into_iter().flatten() {
        let version: String = a["version"].as_str().unwrap_or("").chars().take(12).collect();
        println!(
            "{}  {}  ({} bytes, {}@{})",
            a["sha256"].as_str().unwrap_or(""),
            a["file"].as_str().unwrap_or(""),
            a["size"],
            a["id"].as_str().unwrap_or(""),
            version
        );
    }
    0
}

// -- GET /artifacts/{id}[/{version}] (server.py) ------------------------------

/// What the download route answers.
#[derive(Debug, Clone, PartialEq)]
pub enum DownloadResponse {
    /// 404 with a JSON body -- unknown id, wrong version, missing scope and
    /// no artifact toolkit are one indistinguishable answer (FR-7.7).
    NotFound { status: u16, content_type: &'static str, body: String },
    /// 200: stream `ArtifactStore::stream(&artifact)` as the body with
    /// these headers. If the stream yields an `IntegrityError`, log
    /// `"Artifact {id} changed on disk; download aborted"` (error level)
    /// and abort the response.
    Stream { artifact: Artifact, media_type: String, headers: Vec<(String, String)> },
}

/// The decision of one download, plus the audit record the HTTP layer
/// writes (`audit.write(...)`) before answering.
#[derive(Debug, Clone, PartialEq)]
pub struct Download {
    pub audit: Value,
    pub response: DownloadResponse,
}

/// `GET /artifacts/{artifact_id}[/{version}]`.
///
/// The same gate as the `artifact` tools: the HTTP layer passes
/// `allowed = identity is not None and artifact_id in <allowed_artifacts of
/// every artifact toolkit> and identity.covers_scope("artifact:<id>")`, and
/// `identity_id` (None for an anonymous request). An empty `version` is
/// treated as absent.
pub fn artifact_download(
    store: &ArtifactStore,
    identity_id: Option<&str>,
    allowed: bool,
    artifact_id: &str,
    version: Option<&str>,
) -> Download {
    let version = version.filter(|v| !v.is_empty());
    let art = if allowed { store.get(artifact_id, version) } else { None };
    let audit = json!({
        "kind": "artifact_download", "identity": identity_id,
        "artifact": artifact_id, "version": version,
        "outcome": if art.is_some() { "ok" } else { "denied" },
        "sha256": art.map(|a| a.sha256.clone()),
    });
    let response = match art {
        None => DownloadResponse::NotFound {
            status: 404,
            content_type: crate::release_notes::JSON,
            body: crate::release_notes::json_body(&json!({"error": "not found"})),
        },
        Some(art) => DownloadResponse::Stream {
            artifact: art.clone(),
            media_type: art.media_type.clone(),
            headers: vec![
                ("Content-Length".into(), art.size.to_string()),
                ("Content-Disposition".into(), format!("attachment; filename=\"{}\"", art.file)),
                ("ETag".into(), format!("\"{}\"", art.sha256)),
                ("X-Artifact-SHA256".into(), art.sha256.clone()),
                ("X-Artifact-Version".into(), art.version.clone()),
                ("X-Artifact-Commit".into(), art.commit.clone()),
            ],
        },
    };
    Download { audit, response }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "7aa7b394cb713162db98aad29c91c342508a49c7";
    const CONTRACT: &str = "example-doc";
    const ADAPTER: &str = "example-kit";
    const DOC_FILE: &str = "EXAMPLE.md";
    const KIT_FILE: &str = "example-kit.tar.gz";

    fn fixture_sources() -> Vec<Source> {
        vec![
            Source {
                id: CONTRACT.into(),
                kind: SourceKind::File,
                path: "docs/EXAMPLE.md".into(),
                file: DOC_FILE.into(),
                media_type: "text/markdown; charset=utf-8".into(),
                text: true,
            },
            Source {
                id: ADAPTER.into(),
                kind: SourceKind::Tree,
                path: "kit".into(),
                file: KIT_FILE.into(),
                media_type: "application/gzip".into(),
                text: false,
            },
        ]
    }

    fn repo(tmp: &Path) -> String {
        let root = tmp.join("repo");
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("docs/EXAMPLE.md"), b"# Example document\r\n\nreleased with the image\n").unwrap();
        std::fs::create_dir_all(root.join("kit/pkg/__pycache__")).unwrap();
        std::fs::write(root.join("kit/pkg/main.py"), "print('hello')\n").unwrap();
        std::fs::write(root.join("kit/pkg/__pycache__/main.cpython-312.pyc"), b"\0").unwrap();
        std::fs::create_dir_all(root.join("kit/out")).unwrap();
        std::fs::write(root.join("kit/out/generated.txt"), "x").unwrap();
        std::fs::write(root.join("kit/README.md"), "kit\n").unwrap();
        root.to_str().unwrap().to_string()
    }

    fn setup() -> (tempfile::TempDir, String, String) {
        let tmp = tempfile::tempdir().unwrap();
        let root = repo(tmp.path());
        let out = tmp.path().join("artifacts").to_str().unwrap().to_string();
        build(&root, &out, COMMIT, "0.52.0", &fixture_sources()).unwrap();
        (tmp, root, out)
    }

    /// Member names of an uncompressed ustar archive (no pax handling).
    fn tar_names(raw: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        let mut off = 0;
        while off + 512 <= raw.len() && raw[off] != 0 {
            let header = &raw[off..off + 512];
            let name = String::from_utf8_lossy(&header[..100]).trim_end_matches('\0').to_string();
            let size = usize::from_str_radix(std::str::from_utf8(&header[124..135]).unwrap(), 8).unwrap();
            names.push(name);
            off += 512 + size.div_ceil(512) * 512;
        }
        names
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(data).read_to_end(&mut out).unwrap();
        out
    }

    #[test]
    fn build_is_deterministic_and_bound_to_the_commit() {
        let (tmp, root, out) = setup();
        let again = tmp.path().join("again").to_str().unwrap().to_string();
        build(&root, &again, COMMIT, "0.52.0", &fixture_sources()).unwrap();
        let m1 = std::fs::read(format!("{out}/manifest.json")).unwrap();
        let m2 = std::fs::read(format!("{again}/manifest.json")).unwrap();
        assert_eq!(m1, m2);
        let m: Value = serde_json::from_slice(&m1).unwrap();
        assert_eq!(m["commit"], COMMIT);
        assert!(m["artifacts"].as_array().unwrap().iter().all(|a| a["version"] == COMMIT));
        let contract = replace_crlf(&std::fs::read(format!("{root}/docs/EXAMPLE.md")).unwrap());
        let entry = m["artifacts"].as_array().unwrap().iter().find(|a| a["id"] == CONTRACT).unwrap();
        assert_eq!(entry["sha256"], hex::encode(Sha256::digest(&contract)));
        assert_eq!(
            std::fs::read(format!("{out}/{KIT_FILE}")).unwrap(),
            std::fs::read(format!("{again}/{KIT_FILE}")).unwrap()
        );
    }

    #[test]
    fn tree_archive_contains_the_tree_and_nothing_generated() {
        let (_tmp, _root, out) = setup();
        let names = tar_names(&gunzip(&std::fs::read(format!("{out}/{KIT_FILE}")).unwrap()));
        assert!(names.contains(&format!("{ADAPTER}/pkg/main.py")));
        assert!(names.contains(&format!("{ADAPTER}/README.md")));
        assert!(!names.iter().any(|n| n.contains("/out/") || n.ends_with(".pyc") || n.contains("__pycache__")));
        assert_eq!(names, [format!("{ADAPTER}/README.md"), format!("{ADAPTER}/pkg/main.py")]);
    }

    #[test]
    fn tampered_file_is_disabled() {
        let (_tmp, _root, out) = setup();
        std::fs::write(format!("{out}/{DOC_FILE}"), "tampered").unwrap();
        let store = ArtifactStore::new(out);
        assert!(store.get(CONTRACT, None).is_none());
        assert_eq!(store.disabled[CONTRACT], "sha256 mismatch");
        assert!(store.get(ADAPTER, None).is_some());
    }

    #[test]
    fn missing_directory_serves_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(ArtifactStore::new(tmp.path().join("nowhere").to_str().unwrap()).list().is_empty());
    }

    #[test]
    fn the_image_builds_a_commit_bound_manifest_without_the_removed_adapter() {
        assert!(!SOURCES.iter().any(|s| s.id == "hermes-adapter-contract" || s.id == "hermes-recovery-adapter"));
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("image").to_str().unwrap().to_string();
        let manifest =
            build(tmp.path().join("empty-checkout").to_str().unwrap(), &out, COMMIT, "0.52.0", SOURCES).unwrap();
        assert_eq!(manifest["commit"], COMMIT);
        assert_eq!(manifest["artifacts"], json!([]));
        let store = ArtifactStore::new(out.clone());
        assert_eq!(store.commit, COMMIT);
        assert!(store.list().is_empty());
        assert_eq!(
            std::fs::read_to_string(format!("{out}/manifest.json")).unwrap(),
            format!("{{\n  \"artifacts\": [],\n  \"commit\": \"{COMMIT}\",\n  \"release\": \"0.52.0\",\n  \"schema\": 1\n}}\n")
        );
    }

    #[test]
    fn get_with_version_prefix_and_public_view() {
        let (_tmp, _root, out) = setup();
        let store = ArtifactStore::new(out);
        let art = store.get(CONTRACT, Some(&COMMIT[..7])).unwrap();
        assert_eq!(art.public()["download_path"], format!("/artifacts/{CONTRACT}/{COMMIT}"));
        assert_eq!(art.public()["commit"], COMMIT);
        assert!(store.get(CONTRACT, Some("deadbee")).is_none());
        assert!(store.get(CONTRACT, Some("7aa7b3")).is_none()); // too short for VERSION_RE
        assert!(store.get(CONTRACT, Some("")).is_some());
        assert!(store.get("../etc", None).is_none());
        let ids: Vec<&str> = store.list().iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, [CONTRACT, ADAPTER]);
    }

    #[test]
    fn read_text_and_its_refusals() {
        let (_tmp, _root, out) = setup();
        let store = ArtifactStore::new(out.clone());
        let doc = store.get(CONTRACT, None).unwrap().clone();
        assert!(store.read_text(&doc, 200000).unwrap().starts_with("# Example document\n"));
        let kit = store.get(ADAPTER, None).unwrap().clone();
        assert_eq!(store.read_text(&kit, 200000).unwrap_err().to_string(), "not a text artifact");
        assert_eq!(
            store.read_text(&doc, 3).unwrap_err().to_string(),
            format!("{} bytes exceed the output limit of 3", doc.size)
        );
        // Changed after startup: the stream raises at the end.
        std::fs::write(format!("{out}/{DOC_FILE}"), "changed").unwrap();
        let err = store.read_text(&doc, 200000).unwrap_err();
        assert!(err.is_value_or_integrity());
        assert_eq!(err.to_string(), format!("{CONTRACT}: content changed since startup"));
    }

    #[test]
    fn stream_yields_verified_bytes() {
        let (_tmp, _root, out) = setup();
        let store = ArtifactStore::new(out.clone());
        let kit = store.get(ADAPTER, None).unwrap().clone();
        let bytes: Vec<u8> = store.stream(&kit).map(|c| c.unwrap()).flatten().collect();
        assert_eq!(bytes, std::fs::read(format!("{out}/{KIT_FILE}")).unwrap());
        std::fs::remove_file(format!("{out}/{KIT_FILE}")).unwrap();
        let mut stream = store.stream(&kit);
        assert!(matches!(stream.next(), Some(Err(StreamError::Io { .. }))));
        assert!(stream.next().is_none());
    }

    #[test]
    fn http_download_decision() {
        let (_tmp, _root, out) = setup();
        let store = ArtifactStore::new(out);
        let ok = artifact_download(&store, Some("homelab"), true, ADAPTER, Some(&COMMIT[..12]));
        assert_eq!(ok.audit["outcome"], "ok");
        let DownloadResponse::Stream { artifact, media_type, headers } = &ok.response else { panic!() };
        assert_eq!(media_type, "application/gzip");
        assert!(headers.contains(&("X-Artifact-Commit".into(), COMMIT.into())));
        assert!(headers.contains(&("X-Artifact-SHA256".into(), artifact.sha256.clone())));
        assert!(headers.contains(&("Content-Disposition".into(), format!("attachment; filename=\"{KIT_FILE}\""))));
        let hidden = artifact_download(&store, Some("other"), false, ADAPTER, None);
        let unknown = artifact_download(&store, Some("homelab"), true, "nope", None);
        assert_eq!(hidden.response, unknown.response);
        let DownloadResponse::NotFound { status, body, .. } = &hidden.response else { panic!() };
        assert_eq!((*status, body.as_str()), (404, r#"{"error":"not found"}"#));
        assert_eq!(
            crate::pyjson::dumps(&hidden.audit),
            r#"{"kind": "artifact_download", "identity": "other", "artifact": "example-kit", "version": null, "outcome": "denied", "sha256": null}"#
        );
    }

    #[test]
    fn malformed_manifests() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::fs::write(format!("{dir}/manifest.json"), "{\"schema\": 2}").unwrap();
        assert!(ArtifactStore::new(dir).list().is_empty());
        std::fs::write(format!("{dir}/manifest.json"), "not json").unwrap();
        assert!(ArtifactStore::new(dir).list().is_empty());
        std::fs::write(
            format!("{dir}/manifest.json"),
            r#"{"schema": 1.0, "commit": "c", "artifacts": [
                {"id": "Bad", "version": "c", "file": "x", "media_type": "m", "text": true, "size": 0, "sha256": "", "source": "s"},
                {"id": "ok-id", "version": "c", "file": "../x", "media_type": "m", "text": true, "size": 0, "sha256": "", "source": "s"},
                {"id": "gone", "version": "c", "file": "gone.txt", "media_type": "m", "text": true, "size": 0, "sha256": "", "source": "s"}]}"#,
        )
        .unwrap();
        let store = ArtifactStore::new(dir);
        assert_eq!(store.commit, "c");
        assert_eq!(store.disabled["Bad"], "invalid manifest entry");
        assert_eq!(store.disabled["ok-id"], "invalid manifest entry");
        assert_eq!(
            store.disabled["gone"],
            format!("unreadable: [Errno 2] No such file or directory: '{dir}/gone.txt'")
        );
    }

    #[test]
    fn utf8_error_text_matches_python() {
        let e = |b: &[u8]| utf8_error_text(b, &std::str::from_utf8(b).unwrap_err());
        assert_eq!(e(b"\xff"), "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte");
        assert_eq!(e(b"a\xe2\x28"), "'utf-8' codec can't decode byte 0xe2 in position 1: invalid continuation byte");
        assert_eq!(e(b"a\xe2"), "'utf-8' codec can't decode byte 0xe2 in position 1: unexpected end of data");
        assert_eq!(e(b"a\xe2\x82"), "'utf-8' codec can't decode bytes in position 1-2: unexpected end of data");
    }

    #[test]
    fn cli_requires_its_arguments_and_builds() {
        assert_eq!(main("gk", &[]), 2);
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("o").to_str().unwrap().to_string();
        let args: Vec<String> =
            ["--out", &out, "--comm", COMMIT, "--release=1.0.0"].iter().map(|s| s.to_string()).collect();
        assert_eq!(main("gk", &args), 0);
        assert!(Path::new(&format!("{out}/manifest.json")).is_file());
    }

    /// Byte-identical to Python for the same tree, when the reference venv
    /// is present (it is in the porting environment; skipped elsewhere).
    #[test]
    fn tar_gz_is_byte_identical_to_python() {
        let python = "/tmp/claude-0/venv/bin/python";
        if !Path::new(python).exists() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = repo(tmp.path());
        let kit = format!("{root}/kit");
        // Extra shapes: CRLF in an extensionless file, a long name (pax),
        // a non-ASCII name (pax), binary content, a big file.
        std::fs::write(format!("{kit}/Makefile"), "a\r\nb\r\n").unwrap();
        std::fs::write(format!("{kit}/data.bin"), b"x\r\n\x00\xff").unwrap();
        let long = "d".repeat(120);
        std::fs::write(format!("{kit}/{long}.txt"), "long\r\n").unwrap();
        std::fs::write(format!("{kit}/caf\u{e9}.md"), "\u{fc}\n").unwrap();
        let big: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        std::fs::write(format!("{kit}/big.dat"), &big).unwrap();
        std::fs::create_dir_all(format!("{kit}/.pytest_cache")).unwrap();
        std::fs::write(format!("{kit}/.pytest_cache/x"), "x").unwrap();
        let ours = deterministic_tar(&root, "kit", ADAPTER).unwrap();
        let script = format!(
            "import sys; from gatekeeper.artifacts import _deterministic_tar as t; \
             sys.stdout.buffer.write(t({root:?}, 'kit', {ADAPTER:?}))"
        );
        let output = std::process::Command::new(python).args(["-c", &script]).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(gunzip(&ours), gunzip(&output.stdout), "uncompressed tar differs");
        assert_eq!(ours, output.stdout, "gzip bytes differ");
    }
}
