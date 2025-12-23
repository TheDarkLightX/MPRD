#![no_main]

use libfuzzer_sys::fuzz_target;
#[cfg(not(feature = "asde"))]
compile_error!("asde_allocation_v1 requires the `asde` feature (build with `--features asde`).");

use mprd_asde::{capped_proportional_allocate_v1, AllocationInputV1};

type PublicKeyBytes = [u8; 32];

const MAX_ITEMS: usize = 64;

struct Cursor<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, index: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.index.checked_add(n)?;
        if end > self.bytes.len() {
            return None;
        }
        let out = &self.bytes[self.index..end];
        self.index = end;
        Some(out)
    }

    fn take_u8(&mut self) -> Option<u8> {
        Some(*self.take(1)?.first()?)
    }

    fn take_u128_le(&mut self) -> Option<u128> {
        let s = self.take(16)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(s);
        Some(u128::from_le_bytes(out))
    }

    fn take_pk(&mut self) -> Option<PublicKeyBytes> {
        let s = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        Some(out)
    }
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    let n = match c.take_u8() {
        Some(x) => (x as usize).min(MAX_ITEMS),
        None => return,
    };

    let mut inputs: Vec<AllocationInputV1> = Vec::with_capacity(n);
    for _ in 0..n {
        let pk = match c.take_pk() {
            Some(x) => x,
            None => return,
        };
        let weight = match c.take_u128_le() {
            Some(x) => x % 10_000u128,
            None => return,
        };
        let cap_mode = match c.take_u8() {
            Some(x) => x % 3,
            None => return,
        };
        let cap_sfa = match cap_mode {
            0 => None, // unbounded (should fail-closed on overflow in some mixes)
            1 => Some(0),
            _ => match c.take_u128_le() {
                Some(x) => Some(x % 1_000_000u128),
                None => return,
            },
        };
        inputs.push(AllocationInputV1 {
            user_pubkey: pk,
            weight,
            cap_sfa,
        });
    }

    let budget = match c.take_u128_le() {
        Some(x) => x % 1_000_000u128,
        None => return,
    };

    let out = match capped_proportional_allocate_v1(&inputs, budget) {
        Ok(x) => x,
        Err(_) => return, // fail-closed is acceptable; panics are not.
    };

    // Outputs must be sorted and never exceed the budget.
    let mut total = 0u128;
    for w in out.windows(2) {
        assert!(w[0].user_pubkey <= w[1].user_pubkey);
    }
    for o in &out {
        if let Some(item) = inputs.iter().find(|i| i.user_pubkey == o.user_pubkey) {
            if let Some(cap) = item.cap_sfa {
                assert!(o.amount_sfa <= cap);
            }
        }
        total = total.checked_add(o.amount_sfa).expect("sum overflow");
    }
    assert!(total <= budget);
});
