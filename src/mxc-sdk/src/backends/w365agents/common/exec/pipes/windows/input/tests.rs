// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::{align_of, size_of, size_of_val};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::Foundation::OBJECT_NAME_INFORMATION;
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, FILE_TYPE_CHAR, PIPE_ACCESS_INBOUND,
};
use windows::Win32::System::Console::{GetConsoleMode, CONSOLE_MODE};
use windows::Win32::System::Pipes::{CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE};

use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};

use super::{classify_handle, classify_owned, classify_stdin, decode_object_name, RelayedInput};

fn assert_rejected(input: Result<RelayedInput, MxcError>) {
    let error = input.expect_err("unsupported stdin must not become EOF or a reader");
    assert_eq!(error.code, MxcErrorCode::PolicyValidation);
    assert!(
        error.message.contains("Piped"),
        "an error must explain alternatives"
    );
}

fn pipe_input() -> io::Result<()> {
    let (mut original, mut writer) = io::pipe()?;
    assert_rejected(classify_handle(writer.as_raw_handle()));
    let bytes = [0, 0xFF, b'\r', b'\n', 0x80];
    writer.write_all(&bytes)?;
    let RelayedInput::Pipe(mut duplicate) =
        classify_handle(original.as_raw_handle()).map_err(io::Error::other)?
    else {
        panic!("a synchronous pipe must be supported");
    };
    let mut unread = [0; 5];
    original.read_exact(&mut unread)?;
    assert_eq!(unread, bytes, "classification consumed input");
    drop(original);
    writer.write_all(b"owned duplicate")?;
    drop(writer);
    let mut remaining = Vec::new();
    duplicate.read_to_end(&mut remaining)?;
    assert_eq!(remaining, b"owned duplicate");
    Ok(())
}

fn closed_input() -> io::Result<()> {
    assert!(matches!(
        classify_handle(ptr::null_mut()),
        Ok(RelayedInput::Eof)
    ));
    assert!(matches!(
        classify_handle(INVALID_HANDLE_VALUE.0),
        Ok(RelayedInput::Eof)
    ));
    let (reader, writer) = io::pipe()?;
    let closed = reader.as_raw_handle();
    drop(reader);
    assert!(matches!(classify_handle(closed), Ok(RelayedInput::Eof)));
    drop(writer);
    Ok(())
}

fn null_input() -> io::Result<()> {
    let null = File::open("NUL")?;
    assert!(matches!(
        classify_handle(null.as_raw_handle()),
        Ok(RelayedInput::Eof)
    ));
    // The watchdog launches this child with NUL stdin, not the parent's input.
    assert!(matches!(classify_stdin(), Ok(RelayedInput::Eof)));
    Ok(())
}

fn disk_input() -> io::Result<()> {
    let file = tempfile::tempfile()?;
    assert_rejected(classify_handle(file.as_raw_handle()));
    Ok(())
}

fn overlapped_input() -> io::Result<()> {
    let name: Vec<u16> = format!(r"\\.\pipe\mxc-w365-input-{}", uuid::Uuid::new_v4())
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: the name is terminated and live; no security attributes or
    // pending I/O are involved. This unconnected pipe is used only for queries.
    let raw = unsafe {
        CreateNamedPipeW(
            PCWSTR(name.as_ptr()),
            PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            None,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateNamedPipeW returned a fresh, valid owned handle.
    let pipe = unsafe { OwnedHandle::from_raw_handle(raw.0) };
    assert_rejected(classify_handle(pipe.as_raw_handle()));
    Ok(())
}

fn console_input() -> io::Result<()> {
    let console = File::open("CONIN$")?;
    let mut mode = CONSOLE_MODE::default();
    // SAFETY: the file remains owned and mode is writable. This query does not
    // alter the console, and only this child has CREATE_NEW_CONSOLE.
    unsafe { GetConsoleMode(HANDLE(console.as_raw_handle()), &mut mode) }
        .map_err(io::Error::other)?;
    assert_rejected(classify_handle(console.as_raw_handle()));
    Ok(())
}

fn unproven_character_input() -> io::Result<()> {
    let null = File::open("NUL")?;
    assert_rejected(classify_owned(null.into(), FILE_TYPE_CHAR, |_| Ok(false)));
    let null = File::open("NUL")?;
    assert_rejected(classify_owned(null.into(), FILE_TYPE_CHAR, |_| {
        Err(MxcError::policy_validation("name query failed; use Piped"))
    }));
    Ok(())
}

pub(crate) fn run_case(case: &str) -> io::Result<()> {
    match case {
        "input_pipe" => pipe_input(),
        "input_closed" => closed_input(),
        "input_null" => null_input(),
        "input_disk" => disk_input(),
        "input_overlapped" => overlapped_input(),
        "input_console" => console_input(),
        "input_unproven_character" => unproven_character_input(),
        _ => Err(io::Error::other("unknown Windows input probe")),
    }
}

fn header(storage: &mut [u64]) -> &mut OBJECT_NAME_INFORMATION {
    assert!(size_of_val(storage) >= size_of::<OBJECT_NAME_INFORMATION>());
    assert!(align_of::<u64>() >= align_of::<OBJECT_NAME_INFORMATION>());
    // SAFETY: initialized u64 storage is large and aligned; the native header
    // contains only integers and raw pointers, with no invalid bit patterns.
    unsafe { &mut *storage.as_mut_ptr().cast() }
}

fn name_reply(storage: &mut [u64], name: &str) -> u32 {
    let offset = size_of::<OBJECT_NAME_INFORMATION>();
    let units: Vec<u16> = name.encode_utf16().collect();
    let capacity = (units.len() + 1) * size_of::<u16>();
    assert!(offset + capacity <= size_of_val(storage));
    // SAFETY: the initialized allocation has room for the UTF-16 data and a
    // terminator; the header and data do not overlap.
    let pointer = unsafe { storage.as_mut_ptr().byte_add(offset).cast::<u16>() };
    for (index, unit) in units.iter().copied().chain(Some(0)).enumerate() {
        // SAFETY: the checked capacity covers each UTF-16 unit.
        unsafe { pointer.add(index).write(unit) };
    }
    let info = header(storage);
    info.Name.Length = u16::try_from(units.len() * 2).expect("small name fixture");
    info.Name.MaximumLength = u16::try_from(capacity).expect("small name fixture");
    info.Name.Buffer = PWSTR(pointer);
    u32::try_from(offset + capacity).expect("bounded name fixture")
}

#[test]
fn w365_pipe_null_name_requires_exact_device_identity() {
    for (name, expected) in [
        (r"\Device\Null", true),
        (r"\Device\NullExtra", false),
        (r"\Device\Console", false),
        (r"\device\null", false),
    ] {
        let mut storage = [0u64; 128];
        let returned = name_reply(&mut storage, name);
        assert_eq!(decode_object_name(&storage, returned).unwrap(), expected);
    }
}

#[test]
fn w365_pipe_null_name_rejects_malformed_native_replies() {
    for case in [
        "short",
        "oversized",
        "odd_length",
        "short_capacity",
        "odd_capacity",
        "outside",
        "misaligned",
        "inside_header",
        "capacity_outside",
        "null",
    ] {
        let mut storage = [0u64; 128];
        let mut returned = name_reply(&mut storage, r"\Device\Null");
        let base = storage.as_mut_ptr().cast::<u16>();
        match case {
            "short" => returned = size_of::<OBJECT_NAME_INFORMATION>() as u32 - 1,
            "oversized" => returned = size_of_val(&storage) as u32 + 1,
            "odd_length" => header(&mut storage).Name.Length -= 1,
            "short_capacity" => header(&mut storage).Name.MaximumLength -= 4,
            "odd_capacity" => header(&mut storage).Name.MaximumLength -= 1,
            "outside" => header(&mut storage).Name.Buffer = PWSTR(usize::MAX as *mut u16),
            "misaligned" => {
                header(&mut storage).Name.Buffer = PWSTR(base.cast::<u8>().wrapping_add(1).cast())
            }
            "inside_header" => header(&mut storage).Name.Buffer = PWSTR(base),
            "capacity_outside" => header(&mut storage).Name.MaximumLength = u16::MAX - 1,
            "null" => header(&mut storage).Name.Buffer = PWSTR(ptr::null_mut()),
            _ => unreachable!(),
        }
        assert!(
            decode_object_name(&storage, returned).is_err(),
            "malformed reply {case} must not identify NUL"
        );
    }
}
