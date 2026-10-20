// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::validate_init_capabilities;

const VALID_STATUS: &str = concat!(
    "Pid:\t42\n",
    "CapInh:\t0\n",
    "CapPrm:\t0\n",
    "CapEff:\t0\n",
    "CapBnd:\t0\n",
    "CapAmb:\t0\n",
);

const CAPABILITY_FIELDS: [&str; 5] = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];

#[test]
fn unrelated_capability_bits_are_allowed() {
    for mask in [
        "0",
        "00000000000000000",
        "1",
        "aBcDe",
        "100000",
        "400000",
        "8000000000000000",
        "ffffffffffdfffff",
        "FFFFFFFFFFDFFFFF",
    ] {
        let status = VALID_STATUS.replace(":\t0\n", &format!(":\t{mask}\n"));

        assert_eq!(
            validate_init_capabilities(&status, 42),
            Ok(()),
            "rejected mask {mask:?} for PID 42: {status:?}"
        );
    }
}

#[test]
fn hexadecimal_masks_may_have_one_through_sixteen_digits() {
    for width in 1..=16 {
        let mask = format!("{:0width$x}", 1_u64);
        let status = VALID_STATUS.replace(":\t0\n", &format!(":\t{mask}\n"));

        assert_eq!(
            validate_init_capabilities(&status, 42),
            Ok(()),
            "rejected {width}-digit mask {mask:?} for PID 42: {status:?}"
        );
    }
}

#[test]
fn unrelated_status_fields_are_ignored() {
    let status = format!("Name:\tinit\nPPid:\t1\n{VALID_STATUS}CapExtra:\tnot-a-mask\n");

    assert_eq!(
        validate_init_capabilities(&status, 42),
        Ok(()),
        "rejected unrelated fields for PID 42: {status:?}"
    );
}

#[test]
fn sys_admin_in_any_capability_set_is_rejected() {
    for field in CAPABILITY_FIELDS {
        for mask in ["200000", "8000000000200001"] {
            let status =
                VALID_STATUS.replace(&format!("{field}:\t0\n"), &format!("{field}:\t{mask}\n"));

            assert!(
                validate_init_capabilities(&status, 42).is_err(),
                "accepted CAP_SYS_ADMIN in {field}, mask {mask:?}, for PID 42: {status:?}"
            );
        }
    }
}

#[test]
fn missing_capability_sets_are_rejected() {
    for field in CAPABILITY_FIELDS {
        let status = VALID_STATUS.replace(&format!("{field}:\t0\n"), "");

        assert!(
            validate_init_capabilities(&status, 42).is_err(),
            "accepted missing {field} for PID 42: {status:?}"
        );
    }
}

#[test]
fn duplicate_capability_sets_are_rejected() {
    for field in CAPABILITY_FIELDS {
        let status = format!("{VALID_STATUS}{field}:\t0\n");

        assert!(
            validate_init_capabilities(&status, 42).is_err(),
            "accepted duplicate {field} for PID 42: {status:?}"
        );
    }
}

#[test]
fn malformed_capability_masks_are_rejected() {
    for field in CAPABILITY_FIELDS {
        for mask in ["", " \t", "g", "1g", "-1", "0x1", "1 2"] {
            let status =
                VALID_STATUS.replace(&format!("{field}:\t0\n"), &format!("{field}:\t{mask}\n"));

            assert!(
                validate_init_capabilities(&status, 42).is_err(),
                "accepted malformed {field}, mask {mask:?}, for PID 42: {status:?}"
            );
        }
    }
}

#[test]
fn oversized_capability_masks_are_rejected() {
    for field in CAPABILITY_FIELDS {
        for mask in ["10000000000000000", "fffffffffffffffff"] {
            let status =
                VALID_STATUS.replace(&format!("{field}:\t0\n"), &format!("{field}:\t{mask}\n"));

            assert!(
                validate_init_capabilities(&status, 42).is_err(),
                "accepted oversized {field}, mask {mask:?}, for PID 42: {status:?}"
            );
        }
    }
}

#[test]
fn missing_pid_is_rejected() {
    let status = VALID_STATUS.replace("Pid:\t42\n", "");

    assert!(
        validate_init_capabilities(&status, 42).is_err(),
        "accepted missing PID for expected PID 42: {status:?}"
    );
}

#[test]
fn duplicate_pids_are_rejected() {
    for pid in [42, 43] {
        let status = format!("{VALID_STATUS}Pid:\t{pid}\n");

        assert!(
            validate_init_capabilities(&status, 42).is_err(),
            "accepted duplicate PID {pid} for expected PID 42: {status:?}"
        );
    }
}

#[test]
fn malformed_pids_are_rejected() {
    for pid in ["", "not-a-pid", "42 extra", "0x2a"] {
        let status = VALID_STATUS.replace("Pid:\t42\n", &format!("Pid:\t{pid}\n"));

        assert!(
            validate_init_capabilities(&status, 42).is_err(),
            "accepted malformed PID {pid:?} for expected PID 42: {status:?}"
        );
    }
}

#[test]
fn overflowing_pids_are_rejected() {
    for pid in ["4294967338", "18446744073709551658"] {
        let status = VALID_STATUS.replace("Pid:\t42\n", &format!("Pid:\t{pid}\n"));

        assert!(
            validate_init_capabilities(&status, 42).is_err(),
            "accepted overflowing PID {pid:?} for expected PID 42: {status:?}"
        );
    }
}

#[test]
fn mismatched_pid_is_rejected() {
    assert!(
        validate_init_capabilities(VALID_STATUS, 43).is_err(),
        "accepted a mismatched PID for expected PID 43: {VALID_STATUS:?}"
    );
}

#[test]
fn nonpositive_reported_pids_are_rejected() {
    for pid in ["0", "-1"] {
        let status = VALID_STATUS.replace("Pid:\t42\n", &format!("Pid:\t{pid}\n"));

        assert!(
            validate_init_capabilities(&status, 42).is_err(),
            "accepted nonpositive PID {pid:?} for expected PID 42: {status:?}"
        );
    }
}

#[test]
fn zero_expected_pid_is_rejected_even_when_the_status_matches() {
    let status = VALID_STATUS.replace("Pid:\t42\n", "Pid:\t0\n");

    assert!(
        validate_init_capabilities(&status, 0).is_err(),
        "accepted zero expected PID with a matching status: {status:?}"
    );
}

#[test]
fn positive_pid_boundaries_are_accepted() {
    for pid in [1, u32::MAX] {
        let status = VALID_STATUS.replace("Pid:\t42\n", &format!("Pid:\t{pid}\n"));

        assert_eq!(
            validate_init_capabilities(&status, pid),
            Ok(()),
            "rejected matching positive PID {pid}: {status:?}"
        );
    }
}
