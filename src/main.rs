extern crate alloc;
use alloc::ffi::CString;
use nix::{
    libc::SIGCHLD,
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
    while let Ok(states) = waitpid(pid, None) {
        println!("Exit status: {:?}", states);
    }
    println!("Parent process exit")
}
