use std::{
    io::{BufRead, Read, Seek, SeekFrom, Write},
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Result};
use filetime::FileTime;
use nodtool::nod::DiscStream;
use typed_path::{Utf8NativePath, Utf8UnixPath, Utf8UnixPathBuf};
use wasmtime::{
    component::{Component, HasSelf, Linker, Resource, ResourceAny, ResourceTable},
    AsContextMut, Config, Engine, Store, WasmBacktraceDetails,
};

mod bindings {
    wasmtime::component::bindgen!({
        world: "api",
        with: {
            "decomp-toolkit:vfs/host-vfs/host-file": super::HostVfsFile,
        },
    });
}

use bindings::{
    decomp_toolkit::vfs::{host_vfs, types},
    exports::decomp_toolkit::vfs::guest_vfs,
    wasi::logging::logging,
};

use crate::{
    util::file::buf_copy,
    vfs::{
        open_file, open_path, OpenResult, Vfs, VfsError, VfsFile, VfsFileType, VfsMetadata,
        VfsResult,
    },
};

struct VfsPlugin {
    api_pre: bindings::ApiPre<VfsHost>,

    base_store: Store<VfsHost>,
    base_api: bindings::Api,
}

impl VfsPlugin {
    fn instantiate(&mut self, engine: &Engine) -> Result<(Store<VfsHost>, bindings::Api)> {
        let mut store = Store::new(engine, VfsHost::new());
        let api = self.api_pre.instantiate(&mut store)?;
        Ok((store, api))
    }
}

struct PluginState {
    engine: Engine,
    plugins: Vec<VfsPlugin>,
}

static PLUGIN_STATE: once_cell::sync::Lazy<Mutex<PluginState>> = once_cell::sync::Lazy::new(|| {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Mutex::new(PluginState { engine: Engine::new(&config).unwrap(), plugins: Vec::new() })
});

pub fn register_vfs_plugin(
    api_pre: bindings::ApiPre<VfsHost>,
    base_store: Store<VfsHost>,
    base_api: bindings::Api,
) {
    let mut state = PLUGIN_STATE.lock().unwrap();
    state.plugins.push(VfsPlugin { api_pre, base_store, base_api });
}

pub enum OpenPluginResult {
    None(Box<dyn VfsFile>),
    File(Box<dyn VfsFile>),
    Directory(Box<dyn Vfs>),
}

pub fn open_vfs_plugin(
    base: Box<dyn VfsFile>,
    base_path: &str,
    path: &str,
) -> Result<OpenPluginResult> {
    let mut state = PLUGIN_STATE.lock().map_err(|_| anyhow!("Failed to lock VFS plugins state"))?;
    let engine = state.engine.clone();
    for plugin in state.plugins.iter_mut() {
        if !plugin.base_api.decomp_toolkit_vfs_guest_vfs().call_detect(
            &mut plugin.base_store,
            base_path,
            path,
        )? {
            continue; // Plugin does not handle this path
        }

        let (mut store, api) = plugin.instantiate(&engine)?;
        let guest_vfs = api.decomp_toolkit_vfs_guest_vfs();
        guest_vfs.call_init(&mut store, match log::max_level() {
            log::LevelFilter::Off => logging::Level::Critical,
            log::LevelFilter::Error => logging::Level::Error,
            log::LevelFilter::Warn => logging::Level::Warn,
            log::LevelFilter::Info => logging::Level::Info,
            log::LevelFilter::Debug => logging::Level::Debug,
            log::LevelFilter::Trace => logging::Level::Trace,
        })?;
        let host_file = store.data_mut().resource_table.push(HostVfsFile(base.clone()))?;
        match guest_vfs.call_open(&mut store, base_path, path, host_file)?? {
            guest_vfs::OpenResult::None => continue, // Plugin does not handle this path
            guest_vfs::OpenResult::File(resource) => {
                let guest_file = GuestFile {
                    store: Arc::new(Mutex::new(store)),
                    api: Arc::new(api),
                    resource,
                    position: 0,
                    buf_pos: 0,
                    buf: vec![],
                };
                return Ok(OpenPluginResult::File(Box::new(guest_file)));
            }
            guest_vfs::OpenResult::Directory(resource) => {
                let guest_vfs =
                    GuestVfs { store: Arc::new(Mutex::new(store)), api: Arc::new(api), resource };
                return Ok(OpenPluginResult::Directory(Box::new(guest_vfs)));
            }
        }
    }
    Ok(OpenPluginResult::None(base))
}

struct VfsHost {
    resource_table: ResourceTable,
}

impl VfsHost {
    pub fn new() -> Self { Self { resource_table: ResourceTable::new() } }
}

pub fn init() -> Result<()> {
    let engine = PLUGIN_STATE.lock().expect("Failed to lock plugin state").engine.clone();

    let mut linker = Linker::<VfsHost>::new(&engine);
    logging::add_to_linker::<_, HasSelf<_>>(&mut linker, |x| x)?;
    host_vfs::add_to_linker::<_, HasSelf<_>>(&mut linker, |x| x)?;

    let component =
        Component::from_file(&engine, "../mssbkit/target/wasm32-wasip2/release/mssbkit.opt.wasm")?;
    let instance_pre = linker.instantiate_pre(&component)?;
    let api_pre = bindings::ApiPre::new(instance_pre)?;

    let mut store = Store::new(&engine, VfsHost::new());
    let api = api_pre.instantiate(&mut store)?;
    let guest_vfs = api.decomp_toolkit_vfs_guest_vfs();
    guest_vfs.call_init(&mut store, match log::max_level() {
        log::LevelFilter::Off => logging::Level::Critical,
        log::LevelFilter::Error => logging::Level::Error,
        log::LevelFilter::Warn => logging::Level::Warn,
        log::LevelFilter::Info => logging::Level::Info,
        log::LevelFilter::Debug => logging::Level::Debug,
        log::LevelFilter::Trace => logging::Level::Trace,
    })?;
    register_vfs_plugin(api_pre, store, api);
    Ok(())
}

#[derive(Clone)]
struct GuestVfs {
    store: Arc<Mutex<Store<VfsHost>>>,
    api: Arc<bindings::Api>,
    resource: ResourceAny,
}

impl Vfs for GuestVfs {
    fn open(&mut self, path: &Utf8UnixPath) -> VfsResult<Box<dyn VfsFile>> {
        let mut store = self.store.lock().map_err(|e| VfsError::Other(e.to_string()))?;
        let file_resource = self
            .api
            .decomp_toolkit_vfs_guest_vfs()
            .vfs()
            .call_open(&mut *store, self.resource, path.as_str())
            .map_err(|e| VfsError::Other(e.to_string()))?
            .map_err(|e| VfsError::from(e))?;
        Ok(Box::new(GuestFile {
            store: self.store.clone(),
            api: self.api.clone(),
            resource: file_resource,
            position: 0,
            buf_pos: 0,
            buf: vec![],
        }))
    }

    fn exists(&mut self, path: &Utf8UnixPath) -> VfsResult<bool> {
        let mut store = self.store.lock().map_err(|e| VfsError::Other(e.to_string()))?;
        self.api
            .decomp_toolkit_vfs_guest_vfs()
            .vfs()
            .call_exists(&mut *store, self.resource, path.as_str())
            .map_err(|e| VfsError::Other(e.to_string()))?
            .map_err(|e| VfsError::from(e))
    }

    fn read_dir(&mut self, path: &Utf8UnixPath) -> VfsResult<Vec<String>> {
        let mut store = self.store.lock().map_err(|e| VfsError::Other(e.to_string()))?;
        self.api
            .decomp_toolkit_vfs_guest_vfs()
            .vfs()
            .call_read_dir(&mut *store, self.resource, path.as_str())
            .map_err(|e| VfsError::Other(e.to_string()))?
            .map_err(|e| VfsError::from(e))
    }

    fn metadata(&mut self, path: &Utf8UnixPath) -> VfsResult<VfsMetadata> {
        let mut store = self.store.lock().map_err(|e| VfsError::Other(e.to_string()))?;
        let metadata = self
            .api
            .decomp_toolkit_vfs_guest_vfs()
            .vfs()
            .call_metadata(&mut *store, self.resource, path.as_str())
            .map_err(|e| VfsError::Other(e.to_string()))?
            .map_err(|e| VfsError::from(e))?;
        Ok(metadata.into())
    }
}

#[derive(Clone)]
struct GuestFile {
    store: Arc<Mutex<Store<VfsHost>>>,
    api: Arc<bindings::Api>,
    resource: ResourceAny,
    position: u64,
    buf_pos: usize,
    buf: Vec<u8>,
}

impl VfsFile for GuestFile {
    fn map(&mut self) -> std::io::Result<&[u8]> {
        let metadata = self.metadata()?;
        let len: usize = metadata.len.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "File size exceeds maximum buffer size",
            )
        })?;

        let mut store = self.store.lock().map_err(|e| std::io::Error::other(e.to_string()))?;
        let guest_file = self.api.decomp_toolkit_vfs_guest_vfs().file();
        self.buf = Vec::<u8>::with_capacity(metadata.len as usize);
        let mut pos = 0;
        while self.buf.len() < len {
            let mut data = guest_file
                .call_read(
                    &mut *store,
                    self.resource,
                    pos,
                    (len - self.buf.len()).try_into().unwrap_or(u32::MAX),
                )
                .map_err(|e| std::io::Error::other(e))?
                .map_err(|e| std::io::Error::other(e))?;
            if data.is_empty() {
                break; // EOF
            }
            pos += data.len() as u64;
            self.buf.append(&mut data);
        }
        if self.buf.len() != len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "File size mismatch",
            ));
        }
        self.position = 0;
        self.buf_pos = 0;
        Ok(&self.buf)
    }

    fn metadata(&mut self) -> std::io::Result<VfsMetadata> {
        let mut store = self.store.lock().map_err(|e| std::io::Error::other(e.to_string()))?;
        let metadata = self
            .api
            .decomp_toolkit_vfs_guest_vfs()
            .file()
            .call_metadata(&mut *store, self.resource)
            .map_err(|e| std::io::Error::other(e))?
            .map_err(|e| std::io::Error::other(e))?;
        Ok(metadata.into())
    }

    fn into_disc_stream(self: Box<Self>) -> Box<dyn DiscStream> { self }
}

const DEFAULT_BUF_SIZE: usize = 8192;

impl BufRead for GuestFile {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.buf_pos < self.buf.len() {
            return Ok(&self.buf[self.buf_pos..]);
        }

        let mut store = self.store.lock().map_err(|e| std::io::Error::other(e.to_string()))?;
        let guest_file = self.api.decomp_toolkit_vfs_guest_vfs().file();

        let mut pos = self.position;
        self.buf = Vec::<u8>::with_capacity(DEFAULT_BUF_SIZE);
        while self.buf.len() < DEFAULT_BUF_SIZE {
            let mut data = guest_file
                .call_read(
                    &mut *store,
                    self.resource,
                    pos,
                    (DEFAULT_BUF_SIZE - self.buf.len()) as u32,
                )
                .map_err(|e| std::io::Error::other(e))?
                .map_err(|e| std::io::Error::other(e))?;
            if data.is_empty() {
                break; // EOF
            }
            pos += data.len() as u64;
            self.buf.append(&mut data);
        }

        self.buf_pos = 0;
        Ok(&self.buf)
    }

    fn consume(&mut self, amount: usize) {
        self.position += amount as u64;
        self.buf_pos += amount;
    }
}

impl Read for GuestFile {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let buf = self.fill_buf()?;
        let len = buf.len().min(out.len());
        out[..len].copy_from_slice(&buf[..len]);
        self.consume(len);
        Ok(len)
    }
}

impl Seek for GuestFile {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                let metadata = self.metadata()?;
                metadata.len.saturating_add_signed(offset)
            }
            SeekFrom::Current(offset) => self.position.saturating_add_signed(offset),
        };
        let buf_start = self.position.saturating_sub(self.buf_pos as u64);
        if new_pos < buf_start || new_pos >= buf_start + self.buf.len() as u64 {
            // Reset buffer if seek position is outside the current buffer range
            self.buf.clear();
            self.buf_pos = 0;
        } else {
            // Adjust buffer position if within the current buffer range
            self.buf_pos = (new_pos - buf_start) as usize;
        }
        self.position = new_pos;
        Ok(new_pos)
    }
}

impl logging::Host for VfsHost {
    fn log(&mut self, level: logging::Level, context: String, message: String) {
        match level {
            logging::Level::Trace => log::trace!(target: "wasm", "[{}] {}", context, message),
            logging::Level::Debug => log::debug!(target: "wasm", "[{}] {}", context, message),
            logging::Level::Info => log::info!(target: "wasm", "[{}] {}", context, message),
            logging::Level::Warn => log::warn!(target: "wasm", "[{}] {}", context, message),
            logging::Level::Error => log::error!(target: "wasm", "[{}] {}", context, message),
            logging::Level::Critical => panic!("[{}] {}", context, message),
        }
    }
}

impl host_vfs::Host for VfsHost {}

pub struct HostVfsFile(Box<dyn VfsFile>);

impl host_vfs::HostHostFile for VfsHost {
    fn read(
        &mut self,
        resource: Resource<HostVfsFile>,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, String> {
        let file =
            self.resource_table.get_mut(&resource).map_err(|_| "File not found".to_string())?;
        let mut data = vec![0; size as usize];
        file.0.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
        let mut len = 0usize;
        while len < size as usize {
            match file.0.read(&mut data[len..]) {
                Ok(0) => break, // EOF
                Ok(n) => len += n,
                Err(e) => return Err(e.to_string()),
            }
        }
        if len < size as usize {
            data.truncate(len);
        }
        Ok(data)
    }

    fn metadata(&mut self, resource: Resource<HostVfsFile>) -> Result<types::VfsMetadata, String> {
        let file =
            self.resource_table.get_mut(&resource).map_err(|_| "File not found".to_string())?;
        file.0.metadata().map(|metadata| metadata.into()).map_err(|e| e.to_string())
    }

    fn drop(&mut self, resource: Resource<HostVfsFile>) -> Result<()> {
        self.resource_table.delete(resource)?;
        Ok(())
    }
}

impl From<VfsMetadata> for types::VfsMetadata {
    fn from(metadata: VfsMetadata) -> Self {
        Self {
            file_type: metadata.file_type.into(),
            size: metadata.len,
            modified: metadata.mtime.map(|t| t.unix_seconds()),
        }
    }
}

impl From<types::VfsMetadata> for VfsMetadata {
    fn from(metadata: types::VfsMetadata) -> Self {
        Self {
            file_type: metadata.file_type.into(),
            len: metadata.size,
            mtime: metadata.modified.map(|t| FileTime::from_unix_time(t, 0)),
        }
    }
}

impl From<VfsFileType> for types::VfsFileType {
    fn from(file_type: VfsFileType) -> Self {
        match file_type {
            VfsFileType::File => types::VfsFileType::File,
            VfsFileType::Directory => types::VfsFileType::Directory,
        }
    }
}

impl From<types::VfsFileType> for VfsFileType {
    fn from(file_type: types::VfsFileType) -> Self {
        match file_type {
            types::VfsFileType::File => VfsFileType::File,
            types::VfsFileType::Directory => VfsFileType::Directory,
        }
    }
}

impl From<VfsError> for types::VfsError {
    fn from(value: VfsError) -> Self {
        match value {
            VfsError::NotFound => types::VfsError::NotFound,
            VfsError::NotADirectory => types::VfsError::NotADirectory,
            VfsError::IsADirectory => types::VfsError::IsADirectory,
            VfsError::IoError(e) => types::VfsError::Other(e.to_string()),
            VfsError::Other(e) => types::VfsError::Other(e),
        }
    }
}

impl From<types::VfsError> for VfsError {
    fn from(value: types::VfsError) -> Self {
        match value {
            types::VfsError::NotFound => VfsError::NotFound,
            types::VfsError::NotADirectory => VfsError::NotADirectory,
            types::VfsError::IsADirectory => VfsError::IsADirectory,
            types::VfsError::Other(e) => VfsError::Other(e),
        }
    }
}
