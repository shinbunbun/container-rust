use nix::sched::{clone, CloneFlags};

fn child_fn() -> isize {
    0
}

fn main() {
    // let flags = CloneFlags
    let child = Box::new(child_fn);
    let child_stack = &mut [0; 1024];
    let flags = CloneFlags::CLONE_NEWIPC | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWUSER;
    let pid = unsafe { clone(child, child_stack, flags, None) };
    match pid {
        Ok(pid) => {
            println!("Child pid: {}", pid);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }
}
