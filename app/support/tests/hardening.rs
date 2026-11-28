use std::sync::Arc;
use webprobe_support::sync::Mutex;

#[test]
fn hardening_into_inner_recovers_owned_value_after_poison() {
    let value = Mutex::new(vec![1]);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        value.lock().push(2);
        panic!("poison before ownership transfer");
    }));
    assert!(panic.is_err());
    assert_eq!(value.into_inner(), [1, 2]);
}

#[test]
fn hardening_lock_after_poison_does_not_panic_and_keeps_the_value() {
    let value = Mutex::new(vec![1]);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        value.lock().push(2);
        panic!("poison the lock");
    }));
    assert!(panic.is_err());
    // No `.unwrap()`: the guard is returned, recovered after the poison.
    let mut guard = value.lock();
    guard.push(3);
    drop(guard);
    assert_eq!(value.lock().len(), 3);
}

#[test]
fn hardening_repeated_poison_recovery_keeps_mutations_visible() {
    let value = Arc::new(Mutex::new(Vec::new()));
    for n in 0..3 {
        let worker = value.clone();
        assert!(
            std::thread::spawn(move || {
                let mut guard = worker.lock();
                guard.push(n);
                panic!("worker failure");
            })
            .join()
            .is_err()
        );
        assert_eq!(value.lock().len(), n + 1);
    }
    assert_eq!(Arc::try_unwrap(value).unwrap().into_inner(), [0, 1, 2]);
}

#[test]
fn hardening_default_and_into_inner_keep_non_copy_values() {
    let value: Mutex<Vec<String>> = Mutex::default();
    value.lock().push("owned".into());
    assert_eq!(value.into_inner(), ["owned"]);
}
