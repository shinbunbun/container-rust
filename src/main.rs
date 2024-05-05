extern crate alloc;
use std::{fs::write, io::Error, path::Path};

use alloc::ffi::CString;
use nix::{
    libc::{getgid, getuid, SIGCHLD},
    sched::{clone, CloneFlags},
    sys::wait::waitpid,
    unistd::execv,
};

fn child_fn() -> isize {
    println!("staet child process");
    let c = CString::new("/bin/sh").unwrap();
    let argv = [CString::new("sh").unwrap()];
    match execv(&c, &argv) {
        Ok(i) => {
            println!("Success: {}", i);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    };
    0
}

fn write_id_mapping(
    container_id: u32,
    host_id: u32,
    length: u8,
    map_file: &str,
) -> Result<(), Error> {
    let mapping = format!("{} {} {}", container_id, host_id, length);
    write_file(map_file, mapping)?;
    Ok(())
}

fn write_file<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<(), Error> {
    let path = path.as_ref();
    write(path, contents)?;
    Ok(())
}

fn main() {
    println!("Parent pid: {}", std::process::id());

    let cb = Box::new(child_fn);
    let child_stack = &mut [0; 1024];
    let flags = CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUSER;
    let pid = match unsafe { clone(cb, child_stack, flags, Some(SIGCHLD)) } {
        Ok(pid) => pid,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };
    println!("Child pid: {}", pid);

    let setgroups_file = &format!("/proc/{}/setgroups", pid);
    if let Err(err) = write_file(setgroups_file, "deny") {
        eprintln!("setgroups failed: {}", err)
    }

    let uid_map_file = &format!("/proc/{}/uid_map", pid);
    let uid = unsafe { getuid() };
    if let Err(err) = write_id_mapping(0, uid, 1, uid_map_file) {
        eprintln!("UID mapping failed: {}", err)
    }

    let gid_map_file = &format!("/proc/{}/gid_map", pid);
    let gid = unsafe { getgid() };
    if let Err(err) = write_id_mapping(0, gid, 1, gid_map_file) {
        eprintln!("GID mapping failed: {}", err)
    }

    while let Ok(states) = waitpid(pid, None) {
        println!("Exit status: {:?}", states);
    }
    println!("Parent process exit")
}
