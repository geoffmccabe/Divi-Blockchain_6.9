//! Emit a real DMT record, ready to drop into a transaction.
//!
//! This exists so the record bytes in any test or demo come from the **actual
//! encoder** rather than from a fixture someone typed out. A fixture that drifts
//! from the encoder tests nothing; worse, it tests the fixture.
//!
//! It prints two things: the DVXP payload, and the complete `OP_META` output
//! script. Divi's `createrawtransaction` accepts a hex script as an output key,
//! so the second line can be pasted straight in with a value of 0.
//!
//! ```text
//! cargo run --example emit_record -- issue 1000
//! cargo run --example emit_record -- send 301 1 250 0 aabb..(40 hex)
//! cargo run --example emit_record -- burn 301 1 100
//! cargo run --example emit_record -- lock 301 1
//! ```
//!
//! Regtest only. Nothing here signs or broadcasts: building the bytes and
//! spending money are deliberately separate jobs, which is the same split the
//! wallet uses.

use dmt_indexer::encode;
use dmt_indexer::record::issue::Issue;
use dmt_indexer::record::TokenId;
use dvxp_core::codec::Address;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Wrap a payload in an `OP_META` output script.
///
/// `PUSHDATA1` for anything over 75 bytes, a direct push below that: the two
/// forms Divi's relay policy actually produces, and the two the scanner reads.
fn op_meta_script(payload: &[u8]) -> String {
    let mut s = vec![0x6au8];
    if payload.len() <= 75 {
        s.push(payload.len() as u8);
    } else {
        s.push(0x4c);
        s.push(payload.len() as u8);
    }
    s.extend_from_slice(payload);
    hex(&s)
}

fn token_of(args: &[String], at: usize) -> TokenId {
    TokenId {
        height: args[at].parse().expect("height"),
        tx_index: args[at + 1].parse().expect("tx index"),
    }
}

fn address_of(kind: &str, hash160: &str) -> Address {
    let mut h = [0u8; 20];
    for i in 0..20 {
        h[i] = u8::from_str_radix(&hash160[i * 2..i * 2 + 2], 16).expect("hash160 hex");
    }
    Address { kind: kind.parse().expect("address kind"), hash160: h }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: emit_record <issue|send|burn|lock|mint> ...");
        std::process::exit(2);
    }

    let payload = match args[1].as_str() {
        "issue" => {
            let premine: u64 = args[2].parse().expect("premine");
            encode::issue(&Issue {
                flags: 0,
                decimals: 0,
                ticker: Vec::new(),
                salt: None,
                premine,
                terms: None,
                metadata_ptr: None,
            })
        }
        "send" => encode::send(
            token_of(&args, 2),
            args[4].parse().expect("amount"),
            address_of(&args[5], &args[6]),
        ),
        "burn" => encode::burn(token_of(&args, 2), args[4].parse().expect("amount")),
        "lock" => encode::lock_supply(token_of(&args, 2)),
        "mint" => encode::mint(token_of(&args, 2), None),
        other => {
            eprintln!("unknown record: {other}");
            std::process::exit(2);
        }
    };

    match payload {
        Ok(p) => {
            // Refused here rather than after a fee has been paid is the whole
            // point of the encoder checking anything at all.
            println!("payload {}", hex(&p));
            println!("script  {}", op_meta_script(&p));
            println!("bytes   {}", p.len());
        }
        Err(e) => {
            eprintln!("refused: {e}");
            std::process::exit(1);
        }
    }
}
