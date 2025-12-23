#![no_main]

use libfuzzer_sys::fuzz_target;
#[cfg(not(feature = "asde"))]
compile_error!("asde_voucher_trace_v1 requires the `asde` feature (build with `--features asde`).");

use mprd_asde::{voucher_available_balance_sfa_v1, VoucherGrantV1, VoucherSpendV1};

type PublicKeyBytes = [u8; 32];
type Hash32Bytes = [u8; 32];

const MAX_GRANTS: usize = 48;
const MAX_SPENDS: usize = 64;
const MAX_EPOCH: u64 = 64;

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

    fn take_u32_le(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn take_u64_le(&mut self) -> Option<u64> {
        let s = self.take(8)?;
        Some(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
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

    fn take_hash32(&mut self) -> Option<Hash32Bytes> {
        let s = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(s);
        Some(out)
    }
}

fn clamp_epoch(x: u64) -> u64 {
    // Keep epochs small to avoid pathological loops while still exercising edge cases.
    (x % MAX_EPOCH).max(1)
}

fn reference_voucher_balance_sfa_v1(
    grants: &[VoucherGrantV1],
    spends: &[VoucherSpendV1],
    user_pubkey: PublicKeyBytes,
    at_epoch_id: u64,
) -> core::result::Result<u128, ()> {
    // Sort grants for this user by (expiry_epoch, grant_id) and track remaining balances.
    let mut user_grants: Vec<(u64, u64, u64, u128)> = grants
        .iter()
        .filter(|g| g.user_pubkey == user_pubkey)
        .map(|g| (g.expiry_epoch_id, g.grant_id, g.epoch_id, g.voucher_amount_sfa))
        .collect();
    user_grants.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut remaining: Vec<u128> = user_grants.iter().map(|x| x.3).collect();

    // Sort spends for this user by (spend_epoch, spend_id), filter to <= at_epoch.
    let mut user_spends: Vec<(u64, u64, u128)> = spends
        .iter()
        .filter(|s| s.user_pubkey == user_pubkey && s.spend_epoch_id <= at_epoch_id)
        .map(|s| (s.spend_epoch_id, s.spend_id, s.spend_amount_sfa))
        .collect();
    user_spends.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    // Fail-closed on duplicate spend_id at the same spend_epoch.
    for w in user_spends.windows(2) {
        if w[0].0 == w[1].0 && w[0].1 == w[1].1 {
            return Err(());
        }
    }

    for (spend_epoch, _spend_id, spend_amount) in user_spends {
        let mut need = spend_amount;
        if need == 0 {
            continue;
        }

        for (i, (expiry_epoch, _grant_id, grant_epoch, _amt)) in user_grants.iter().enumerate() {
            if spend_epoch < *grant_epoch || spend_epoch > *expiry_epoch {
                continue;
            }
            let avail = remaining[i];
            if avail == 0 {
                continue;
            }
            let take = if avail < need { avail } else { need };
            remaining[i] = avail - take;
            need -= take;
            if need == 0 {
                break;
            }
        }

        if need != 0 {
            return Err(());
        }
    }

    let mut total = 0u128;
    for (i, (expiry_epoch, _grant_id, grant_epoch, _amt)) in user_grants.iter().enumerate() {
        if at_epoch_id < *grant_epoch || at_epoch_id > *expiry_epoch {
            continue;
        }
        total = total.checked_add(remaining[i]).ok_or(())?;
    }

    Ok(total)
}

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);

    let user = match c.take_pk() {
        Some(x) => x,
        None => return,
    };
    let mut other = match c.take_pk() {
        Some(x) => x,
        None => return,
    };
    if other == user {
        other[0] ^= 0xFF;
    }

    let grants_n = match c.take_u8() {
        Some(x) => (x as usize).min(MAX_GRANTS),
        None => return,
    };
    let spends_n = match c.take_u8() {
        Some(x) => (x as usize).min(MAX_SPENDS),
        None => return,
    };

    let mut grants: Vec<VoucherGrantV1> = Vec::with_capacity(grants_n);
    for i in 0..grants_n {
        let start = match c.take_u64_le() {
            Some(x) => clamp_epoch(x),
            None => return,
        };
        let duration = match c.take_u32_le() {
            Some(x) => (x as u64) % MAX_EPOCH,
            None => return,
        };
        let end = (start + duration).min(MAX_EPOCH);
        let amount = match c.take_u128_le() {
            Some(x) => x % 10_000u128,
            None => return,
        };
        let who = match c.take_u8() {
            Some(b) => {
                if (b & 1) == 0 {
                    user
                } else {
                    other
                }
            }
            None => return,
        };

        grants.push(VoucherGrantV1 {
            grant_id: (i as u64) + 1,
            user_pubkey: who,
            voucher_amount_sfa: amount,
            expiry_epoch_id: end.max(start),
            epoch_id: start,
        });
    }

    let mut spends: Vec<VoucherSpendV1> = Vec::with_capacity(spends_n);
    for i in 0..spends_n {
        let spend_epoch = match c.take_u64_le() {
            Some(x) => clamp_epoch(x),
            None => return,
        };
        let spend_amount = match c.take_u128_le() {
            Some(x) => x % 10_000u128,
            None => return,
        };
        let who = match c.take_u8() {
            Some(b) => {
                if (b & 1) == 0 {
                    user
                } else {
                    other
                }
            }
            None => return,
        };
        let spend_id = match c.take_u64_le() {
            Some(x) => {
                // Allow duplicates (this is a key fail-closed condition).
                (x % 64).max(1)
            }
            None => return,
        };
        let fee_receipt_hash = match c.take_hash32() {
            Some(h) => h,
            None => return,
        };

        spends.push(VoucherSpendV1 {
            spend_id: (i as u64) ^ spend_id,
            user_pubkey: who,
            spend_amount_sfa: spend_amount,
            spend_epoch_id: spend_epoch,
            fee_receipt_hash,
        });
    }

    let at_epoch = match c.take_u64_le() {
        Some(x) => clamp_epoch(x),
        None => return,
    };

    let got = voucher_available_balance_sfa_v1(&grants, &spends, user, at_epoch);
    let expected = reference_voucher_balance_sfa_v1(&grants, &spends, user, at_epoch);

    match (got, expected) {
        (Ok(g), Ok(e)) => assert_eq!(g, e),
        (Err(_), Err(_)) => {}
        (Ok(_), Err(_)) => panic!("fail-open: ASDE accepted a trace the reference rejects"),
        (Err(_), Ok(_)) => panic!("unexpected fail-closed: ASDE rejected a valid trace"),
    }
});
