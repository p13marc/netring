//! Integration tests for packet injection.

#![cfg(feature = "integration-tests")]

mod helpers;

use netring::Injector;

#[test]
fn inject_allocate_send_flush() {
    let mut tx = Injector::builder()
        .interface(helpers::LOOPBACK)
        .build()
        .expect("build injector");

    for i in 0u16..10 {
        let mut slot = tx.allocate(64).expect("allocate slot");
        let buf = slot.data_mut();
        buf[0..6].copy_from_slice(&[0xff; 6]); // broadcast
        buf[6..12].copy_from_slice(&[0x00; 6]); // src
        buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        buf[14..16].copy_from_slice(&i.to_be_bytes());
        slot.set_len(64);
        slot.send();
    }

    let flushed = tx.flush().expect("flush");
    assert_eq!(flushed, 10);
}

#[test]
fn inject_drop_without_send() {
    let mut tx = Injector::builder()
        .interface(helpers::LOOPBACK)
        .build()
        .expect("build injector");

    // Allocate but don't send — should be discarded on drop
    {
        let mut slot = tx.allocate(64).expect("allocate slot");
        slot.data_mut()[0..6].copy_from_slice(&[0xff; 6]);
        slot.set_len(64);
        // drop without send()
    }

    // Flush should report 0 pending
    let flushed = tx.flush().expect("flush");
    assert_eq!(flushed, 0);
}
