// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io;
use std::mem::{align_of, size_of, size_of_val};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::slice;

use windows::Wdk::Foundation::{NtQueryObject, OBJECT_INFORMATION_CLASS, OBJECT_NAME_INFORMATION};
use windows::Wdk::Storage::FileSystem::{
    FileAccessInformation, FileModeInformation, NtQueryInformationFile, FILE_ACCESS_INFORMATION,
    FILE_MODE_INFORMATION, FILE_SYNCHRONOUS_IO_ALERT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows::Win32::Foundation::{
    DuplicateHandle, DUPLICATE_SAME_ACCESS, ERROR_INVALID_HANDLE, HANDLE, INVALID_HANDLE_VALUE,
    STATUS_SUCCESS,
};
use windows::Win32::Storage::FileSystem::{
    GetFileType, FILE_READ_DATA, FILE_TYPE, FILE_TYPE_CHAR, FILE_TYPE_PIPE,
};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::IO::IO_STATUS_BLOCK;

use crate::mxc_common::mxc_error::MxcError;

#[derive(Debug)]
pub(crate) enum RelayedInput {
    Eof,
    Pipe(io::PipeReader),
}

pub(crate) fn classify_stdin() -> Result<RelayedInput, MxcError> {
    classify_handle(io::stdin().as_raw_handle())
}

fn classify_handle(raw: RawHandle) -> Result<RelayedInput, MxcError> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE.0 {
        return Ok(RelayedInput::Eof);
    }
    let mut duplicate = HANDLE::default();
    // SAFETY: these are non-owning OS values, not borrowed Rust handles.
    // DuplicateHandle validates the source; only a successful duplicate is
    // adopted below. The current-process pseudo handle is valid for this call.
    let outcome = unsafe {
        let process = GetCurrentProcess();
        DuplicateHandle(
            process,
            HANDLE(raw),
            process,
            &mut duplicate,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if let Err(error) = outcome {
        return if error.code() == ERROR_INVALID_HANDLE.to_hresult() {
            Ok(RelayedInput::Eof)
        } else {
            Err(unsupported(&format!("could not be duplicated ({error})")))
        };
    }
    // SAFETY: the successful call transferred a new, non-inheritable handle.
    let owned = unsafe { OwnedHandle::from_raw_handle(duplicate.0) };
    // SAFETY: the owned duplicate remains valid throughout classification.
    let kind = unsafe { GetFileType(duplicate) };
    classify_owned(owned, kind, is_null_device)
}

fn classify_owned(
    handle: OwnedHandle,
    kind: FILE_TYPE,
    query_null: impl FnOnce(&OwnedHandle) -> Result<bool, MxcError>,
) -> Result<RelayedInput, MxcError> {
    match kind {
        FILE_TYPE_PIPE => {
            validate_pipe(&handle)?;
            Ok(RelayedInput::Pipe(handle.into()))
        }
        FILE_TYPE_CHAR if query_null(&handle)? => Ok(RelayedInput::Eof),
        _ => Err(unsupported(
            "is not a supported synchronous pipe or NUL device",
        )),
    }
}

fn validate_pipe(handle: &OwnedHandle) -> Result<(), MxcError> {
    let mut mode = FILE_MODE_INFORMATION::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the owned pipe and both initialized output buffers stay live.
    // FileModeInformation queries the open mode without reading pipe data.
    let status = unsafe {
        NtQueryInformationFile(
            HANDLE(handle.as_raw_handle()),
            &mut status_block,
            std::ptr::from_mut(&mut mode).cast(),
            size_of::<FILE_MODE_INFORMATION>() as u32,
            FileModeInformation,
        )
    };
    if status != STATUS_SUCCESS || status_block.Information != size_of::<FILE_MODE_INFORMATION>() {
        return Err(unsupported("has an unproven pipe I/O mode"));
    }
    if mode.Mode & (FILE_SYNCHRONOUS_IO_ALERT.0 | FILE_SYNCHRONOUS_IO_NONALERT.0) == 0 {
        return Err(unsupported("uses unsupported overlapped I/O"));
    }
    let mut access = FILE_ACCESS_INFORMATION::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: the live pipe and initialized buffers match FileAccessInformation.
    let status = unsafe {
        NtQueryInformationFile(
            HANDLE(handle.as_raw_handle()),
            &mut status_block,
            std::ptr::from_mut(&mut access).cast(),
            size_of::<FILE_ACCESS_INFORMATION>() as u32,
            FileAccessInformation,
        )
    };
    if status != STATUS_SUCCESS || status_block.Information != size_of::<FILE_ACCESS_INFORMATION>()
    {
        return Err(unsupported("has unproven pipe read access"));
    }
    if access.AccessFlags & FILE_READ_DATA.0 == 0 {
        return Err(unsupported("does not permit reading pipe data"));
    }
    Ok(())
}

fn is_null_device(handle: &OwnedHandle) -> Result<bool, MxcError> {
    // NUL's fixed name fits in 1 KiB; larger or unproven names fail closed.
    let mut storage = [0u64; 128];
    let mut returned = 0;
    // ObjectNameInformation is class 1 in the WDK; this binding has no named constant.
    let information_class = OBJECT_INFORMATION_CLASS(1);
    // SAFETY: the initialized, aligned output storage and returned length stay
    // live for the bounded query. No returned pointer is dereferenced here.
    let status = unsafe {
        NtQueryObject(
            Some(HANDLE(handle.as_raw_handle())),
            information_class,
            Some(storage.as_mut_ptr().cast()),
            size_of_val(&storage) as u32,
            Some(&mut returned),
        )
    };
    if status != STATUS_SUCCESS {
        return Err(unsupported("could not be identified by its object name"));
    }
    decode_object_name(&storage, returned)
}

fn decode_object_name(storage: &[u64], returned: u32) -> Result<bool, MxcError> {
    let invalid = || unsupported("has an invalid object-name reply");
    let returned = returned as usize;
    let header_size = size_of::<OBJECT_NAME_INFORMATION>();
    if returned < header_size || returned > size_of_val(storage) {
        return Err(invalid());
    }
    // SAFETY: the initialized storage covers the header. All fields are
    // integers or raw pointers; copying the header never follows its pointer.
    let info = unsafe {
        storage
            .as_ptr()
            .cast::<OBJECT_NAME_INFORMATION>()
            .read_unaligned()
    };
    let length = usize::from(info.Name.Length);
    let capacity = usize::from(info.Name.MaximumLength);
    let address = info.Name.Buffer.0.addr();
    let offset = address
        .checked_sub(storage.as_ptr().addr())
        .ok_or_else(invalid)?;
    let end = offset.checked_add(capacity).ok_or_else(invalid)?;
    if length > capacity
        || length % size_of::<u16>() != 0
        || capacity % size_of::<u16>() != 0
        || address % align_of::<u16>() != 0
        || offset < header_size
        || end > returned
    {
        return Err(invalid());
    }
    // SAFETY: the checked UTF-16 range lies wholly in this initialized owned
    // allocation. Derive it from that allocation, not the native reply pointer.
    let name = unsafe {
        slice::from_raw_parts(
            storage.as_ptr().byte_add(offset).cast::<u16>(),
            length / size_of::<u16>(),
        )
    };
    Ok(name.iter().copied().eq(r"\Device\Null".encode_utf16()))
}

fn unsupported(reason: &str) -> MxcError {
    MxcError::policy_validation(format!(
        "W365 Relayed stdin {reason}. Use synchronous piped input, NUL/closed input, \
         or Piped native/FFI execution."
    ))
}

#[cfg(test)]
#[path = "input/tests.rs"]
pub(crate) mod tests;
