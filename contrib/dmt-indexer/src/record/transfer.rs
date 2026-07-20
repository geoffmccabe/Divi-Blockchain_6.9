//! TRANSFER (subtype 0x02) -- move units to one or more addresses (spec §5.2).
//!
//! Groups are sorted ascending by token ID with no duplicates, and the block
//! component is delta-encoded. Canonical ordering is enforced at parse time:
//! if the same transfer could be written two ways, two implementations could
//! disagree about which is valid.

use super::{ensure_drained, malformed, order_key, read_address, TokenId};
use dvxp_core::codec::Address;
use dvxp_core::Ignored;
use dvxp_core::varint::Cursor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payout {
    pub amount: u64,
    pub to: Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub token: TokenId,
    pub payouts: Vec<Payout>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub groups: Vec<Group>,
}

impl Transfer {
    /// Total units moved for one token. `None` on overflow -- the caller must
    /// ignore the whole record rather than wrap (spec §5.2 is all-or-nothing).
    pub fn total_for(&self, token: TokenId) -> Option<u64> {
        let mut sum = 0u64;
        for g in self.groups.iter().filter(|g| g.token == token) {
            for p in &g.payouts {
                sum = sum.checked_add(p.amount)?;
            }
        }
        Some(sum)
    }
}

pub fn parse(body: &[u8]) -> Result<Transfer, Ignored> {
    let mut c = Cursor::new(body);

    let group_count = c.read_varint().map_err(malformed)?;
    if group_count == 0 {
        return Err(Ignored::RuleViolation("transfer with no groups"));
    }

    let mut groups = Vec::new();
    let mut prev: Option<TokenId> = None;

    for _ in 0..group_count {
        // Block is a delta from the previous group's block.
        let delta = c.read_varint().map_err(malformed)?;
        let tx_index = u32::try_from(c.read_varint().map_err(malformed)?)
            .map_err(|_| Ignored::Malformed("tx index out of range"))?;
        let height = match prev {
            None => delta,
            Some(p) => p
                .height
                .checked_add(delta)
                .ok_or(Ignored::Malformed("block delta overflow"))?,
        };
        let token = TokenId { height, tx_index };

        // Strictly ascending. Equal heights require a strictly greater index.
        if let Some(p) = prev {
            if order_key(token) <= order_key(p) {
                return Err(Ignored::RuleViolation("groups not in ascending token order"));
            }
        }
        prev = Some(token);

        let recip_count = c.read_varint().map_err(malformed)?;
        if recip_count == 0 {
            return Err(Ignored::RuleViolation("group with no recipients"));
        }

        let mut payouts = Vec::new();
        for _ in 0..recip_count {
            let amount = c.read_varint().map_err(malformed)?;
            if amount == 0 {
                return Err(Ignored::RuleViolation("zero-amount payout"));
            }
            let to = read_address(&mut c)?;
            payouts.push(Payout { amount, to });
        }
        groups.push(Group { token, payouts });
    }

    ensure_drained(&c)?;
    Ok(Transfer { groups })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dvxp_core::codec::ADDRESS_LEN;
    use dvxp_core::varint::write_varint;

    fn addr(tag: u8) -> Vec<u8> {
        let mut v = vec![0x00];
        v.extend_from_slice(&[tag; 20]);
        v
    }

    /// One group as written on the wire: (block_delta, tx_index, payouts).
    type Spec = (u64, u32, Vec<(u64, u8)>);

    fn build(groups: &[Spec]) -> Vec<u8> {
        let mut v = Vec::new();
        write_varint(&mut v, groups.len() as u64);
        for (delta, idx, payouts) in groups {
            write_varint(&mut v, *delta);
            write_varint(&mut v, *idx as u64);
            write_varint(&mut v, payouts.len() as u64);
            for (amount, tag) in payouts {
                write_varint(&mut v, *amount);
                v.extend_from_slice(&addr(*tag));
            }
        }
        v
    }

    #[test]
    fn parses_a_single_payout() {
        let raw = build(&[(100, 2, vec![(500, 0xaa)])]);
        let t = parse(&raw).unwrap();
        assert_eq!(t.groups.len(), 1);
        assert_eq!(t.groups[0].token, TokenId { height: 100, tx_index: 2 });
        assert_eq!(t.groups[0].payouts[0].amount, 500);
    }

    #[test]
    fn parses_an_airdrop_to_many_recipients() {
        let payouts: Vec<(u64, u8)> = (0..20).map(|i| (10 + i as u64, i)).collect();
        let raw = build(&[(50, 1, payouts)]);
        let t = parse(&raw).unwrap();
        assert_eq!(t.groups[0].payouts.len(), 20);
        assert_eq!(t.total_for(TokenId { height: 50, tx_index: 1 }), Some((10..30).sum()));
        // An airdrop of 20 fits comfortably inside the ~592-byte body budget.
        assert!(raw.len() < 592, "airdrop body was {} bytes", raw.len());
    }

    #[test]
    fn block_deltas_accumulate() {
        let raw = build(&[(100, 0, vec![(1, 1)]), (50, 0, vec![(2, 2)]), (0, 7, vec![(3, 3)])]);
        let t = parse(&raw).unwrap();
        let ids: Vec<TokenId> = t.groups.iter().map(|g| g.token).collect();
        assert_eq!(ids[0], TokenId { height: 100, tx_index: 0 });
        assert_eq!(ids[1], TokenId { height: 150, tx_index: 0 });
        // Zero delta stays in the same block; index must advance.
        assert_eq!(ids[2], TokenId { height: 150, tx_index: 7 });
    }

    #[test]
    fn rejects_non_canonical_ordering() {
        // Same token twice (zero delta, same index).
        let dup = build(&[(10, 3, vec![(1, 1)]), (0, 3, vec![(1, 2)])]);
        assert!(matches!(parse(&dup), Err(Ignored::RuleViolation(_))));
        // Index goes backwards within the same block.
        let backwards = build(&[(10, 5, vec![(1, 1)]), (0, 2, vec![(1, 2)])]);
        assert!(matches!(parse(&backwards), Err(Ignored::RuleViolation(_))));
    }

    #[test]
    fn rejects_empty_and_zero_amounts() {
        assert!(matches!(parse(&build(&[])), Err(Ignored::RuleViolation(_))));
        let no_recips = build(&[(1, 0, vec![])]);
        assert!(matches!(parse(&no_recips), Err(Ignored::RuleViolation(_))));
        let zero = build(&[(1, 0, vec![(0, 1)])]);
        assert!(matches!(parse(&zero), Err(Ignored::RuleViolation(_))));
    }

    #[test]
    fn rejects_truncation_and_trailing_bytes() {
        let raw = build(&[(1, 0, vec![(5, 1)])]);
        let mut extra = raw.clone();
        extra.push(0);
        assert_eq!(parse(&extra), Err(Ignored::TrailingBytes));
        assert!(parse(&raw[..raw.len() - ADDRESS_LEN]).is_err());
        // A huge declared count must not allocate or panic -- it truncates.
        let mut lying = Vec::new();
        write_varint(&mut lying, u64::MAX);
        assert!(parse(&lying).is_err());
    }

    #[test]
    fn total_for_reports_overflow_rather_than_wrapping() {
        let raw = build(&[(1, 0, vec![(u64::MAX, 1), (2, 2)])]);
        let t = parse(&raw).unwrap();
        assert_eq!(t.total_for(TokenId { height: 1, tx_index: 0 }), None);
    }
}
