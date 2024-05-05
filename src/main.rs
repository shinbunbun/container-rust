extern crate alloc;
use std::{
    env,
    fs::{create_dir_all, remove_dir_all, set_permissions, write, Permissions},
    io::Error,
    os::unix::fs::PermissionsExt,
    path::Path,
};

use alloc::ffi::CString;
use nix::{
    libc::{getgid, getuid, CLONE_NEWUTS, SIGCHLD},
    mount::{mount, umount, umount2, MntFlags, MsFlags},
    sched::{clone, CloneFlags},
    sys::wait::waitpid,
    unistd::{chdir, chroot, execv, execve, pivot_root, sethostname},
};

const HOME_DIR: &str = "/home/bunbun";

fn child_fn() -> isize {
    println!("staet child process");
    let c = CString::new("/bin/sh").unwrap();
    let argv = [CString::new("").unwrap()];
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

fn run() -> isize {
    let c = CString::new("/proc/self/exe").unwrap();
    let argv = [
        CString::new("/proc/self/exe").unwrap(),
        CString::new("init").unwrap(),
    ];
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

fn init_container() {
    match sethostname("container") {
        Ok(_) => {
            println!("Set hostname success");
        }
        Err(e) => {
            println!("Set hostname failed: {}", e);
        }
    };
    match mount(
        Some("proc"),
        format!("{}/root/rootfs/proc", HOME_DIR).as_str(),
        Some("proc"),
        MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None::<&str>,
    ) {
        Ok(_) => {
            println!("Mount proc success");
        }
        Err(e) => {
            println!("Mount proc failed: {}", e);
        }
    };
    /* match chroot(format!("{}/root/rootfs", HOME_DIR).as_str()) {
        Ok(_) => {
            println!("Chroot success");
        }
        Err(e) => {
            println!("Chroot failed: {}", e);
        }
    }; */
    match chdir(format!("{}/root", HOME_DIR).as_str()) {
        Ok(_) => {
            println!("Change dir success");
        }
        Err(e) => {
            println!("Change dir failed: {}", e);
        }
    };
    match mount(
        Some("rootfs"),
        format!("{}/root/rootfs", HOME_DIR).as_str(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    ) {
        Ok(_) => {
            println!("Mount rootfs success");
        }
        Err(e) => {
            println!("Mount rootfs failed: {}", e);
        }
    };
    match create_dir_all(format!("{}/root/rootfs/oldrootfs", HOME_DIR)) {
        Ok(_) => {
            println!("Create oldrootfs success");
        }
        Err(e) => {
            println!("Create oldrootfs failed: {}", e);
        }
    };
    let perm = Permissions::from_mode(0o700);
    match set_permissions(format!("{}/root/rootfs/oldrootfs", HOME_DIR), perm) {
        Ok(_) => {
            println!("Set permission success");
        }
        Err(e) => {
            println!("Set permission failed: {}", e);
        }
    };
    match pivot_root(
        format!("{}/root/rootfs", HOME_DIR).as_str(),
        format!("{}/root/rootfs/oldrootfs", HOME_DIR).as_str(),
    ) {
        Ok(_) => {
            println!("Pivot root success");
        }
        Err(e) => {
            println!("Pivot root failed: {}", e);
        }
    };
    match umount2("/oldrootfs", MntFlags::MNT_DETACH) {
        Ok(_) => {
            println!("Umount oldrootfs success");
        }
        Err(e) => {
            println!("Umount oldrootfs failed: {}", e);
        }
    };
    match remove_dir_all("/oldrootfs") {
        Ok(_) => {
            println!("Remove oldrootfs success");
        }
        Err(e) => {
            println!("Remove oldrootfs failed: {}", e);
        }
    };
    match chdir("/") {
        Ok(_) => {
            println!("Change dir success");
        }
        Err(e) => {
            println!("Change dir failed: {}", e);
        }
    };

    let c = CString::new("/bin/sh").unwrap();
    let argv = [CString::new("/bin/sh").unwrap()];
    let envp: Vec<CString> = env::vars()
        .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap())
        .collect();
    // println!("envp: {:?}", envp);
    match execve(&c, &argv, &envp) {
        Ok(i) => {
            println!("Success: {}", i);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    };
}

fn id_mapping(pid: &str) {
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
}

fn main() {
    println!("Parent pid: {}", std::process::id());

    /* let cb = Box::new(child_fn);
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
    println!("Parent process exit") */

    let args = env::args().collect::<Vec<String>>();
    let arg1 = &args[1];
    println!("arg1: {}", arg1);

    match arg1.as_str() {
        "run" => {
            let cb = Box::new(run);
            let child_stack = &mut [0; 1024];
            let flags = CloneFlags::CLONE_NEWIPC
                | CloneFlags::CLONE_NEWNET
                | CloneFlags::CLONE_NEWUSER
                | CloneFlags::CLONE_NEWUTS
                | CloneFlags::CLONE_NEWPID
                | CloneFlags::CLONE_NEWNS;
            let pid = match unsafe { clone(cb, child_stack, flags, Some(SIGCHLD)) } {
                Ok(pid) => pid,
                Err(e) => {
                    println!("Error: {}", e);
                    return;
                }
            };
            id_mapping(&pid.to_string());
            println!("Child pid: {}", pid);
            while let Ok(states) = waitpid(pid, None) {
                println!("Exit status: {:?}", states);
            }
        }
        "init" => {
            init_container();
        }
        _ => {}
    }
    println!("Parent process exit")
}
