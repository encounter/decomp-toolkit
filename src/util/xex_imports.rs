use anyhow::ensure;

fn replace_ordinal(lib_name: &String, ordinal: usize) -> String {
    if lib_name == "xam.xex" {
        return "".to_string();
    }
    else if lib_name == "xboxkrnl.exe" {
        return "".to_string();
    }
    else if lib_name == "xbdm.xex" {
        return "".to_string();
    }
    else if lib_name.contains("createprofile") {
        assert!(ordinal < CREATEPROFILE_FUNCS.len());
        let res = CREATEPROFILE_FUNCS[ordinal];
        assert!(!res.contains("Unused"));
        return res.to_string();
    }
    else {
        return format!("{:04X}", ordinal);
    }
}

const CREATEPROFILE_FUNCS: [&str; 3] = [
    "Unused0",
    "CreateProfile_Register",
    "CreateProfile_Unregister"
];

const CONNECTX_FUNCS: [&str; 25] = [
    "Unused0",
    "CxGetVersion",
    "NbtNetbios",
    "SmbCloseHandle",
    "SmbCreateDirectoryW",
    "SmbCreateFileW",
    "SmbDeleteFileW",
    "SmbFindClose",
    "SmbFindFirstFileW",
    "SmbFindNextFile",
	"SmbFlushFileBuffers",
	"SmbGetDiskFreeSpaceW",
    "SmbGetFileAttributesW",
    "SmbGetFileInformationByHandle",
    "SmbGetFileSize",
    "SmbGetFileTime",
    "SmbMoveFileW",
    "SmbReadFile",
    "SmbRemoveDirectoryW",
    "SmbSetEndOfFile",
    "SmbSetFileAttributesW",
    "SmbSetFilePointer",
    "SmbSetFileTime",
    "SmbStartup",
    "SmbWriteFile",
];

const SYSCALL_FUNCS: [&str; 1] = [
    "todo"
];

const VK_FUNCS: [&str; 1] = [
    "todo"
];

const XAM_FUNCS: [&str; 1] = [
    "todo"
];

const XAPI_FUNCS: [&str; 1] = [
    "todo"
];

const XBDM_FUNCS: [&str; 1] = [
    "todo"
];

const XBOXKRNL_FUNCS: [&str; 1] = [
    "todo"
];