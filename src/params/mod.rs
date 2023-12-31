#[cfg(feature = "ntrup653")]
pub mod params653 {
    pub const P: usize = 653;
    pub const Q: usize = 4621;
    pub const W: usize = 288;
    pub const Q12: usize = (Q - 1) / 2;
    pub const R3_BYTES: usize = (P + 3) / 4;
    pub const RQ_BYTES: usize = P * 2;
    pub const PUBLICKEYS_BYTES: usize = RQ_BYTES;
    pub const SECRETKEYS_BYTES: usize = R3_BYTES * 2;
    pub const DIFFICULT: usize = 4;
}

#[cfg(feature = "ntrup761")]
pub mod params761 {
    pub const P: usize = 761;
    pub const W: usize = 286;
    pub const Q: usize = 4591;
    pub const Q12: usize = (Q - 1) / 2;
    pub const R3_BYTES: usize = (P + 3) / 4;
    pub const RQ_BYTES: usize = P * 2;
    pub const PUBLICKEYS_BYTES: usize = RQ_BYTES;
    pub const SECRETKEYS_BYTES: usize = R3_BYTES * 2;
    pub const DIFFICULT: usize = 6;
}

#[cfg(feature = "ntrup857")]
pub mod params857 {
    pub const P: usize = 857;
    pub const W: usize = 322;
    pub const Q: usize = 5167;
    pub const Q12: usize = (Q - 1) / 2;
    pub const R3_BYTES: usize = (P + 3) / 4;
    pub const RQ_BYTES: usize = P * 2;
    pub const PUBLICKEYS_BYTES: usize = RQ_BYTES;
    pub const SECRETKEYS_BYTES: usize = R3_BYTES * 2;
    pub const DIFFICULT: usize = 8;
}

#[cfg(feature = "ntrup953")]
pub mod params953 {
    pub const P: usize = 953;
    pub const Q: usize = 6343;
    pub const W: usize = 396;
    pub const Q12: usize = (Q - 1) / 2;
    pub const R3_BYTES: usize = (P + 3) / 4;
    pub const RQ_BYTES: usize = P * 2;
    pub const PUBLICKEYS_BYTES: usize = RQ_BYTES;
    pub const SECRETKEYS_BYTES: usize = R3_BYTES * 2;
    pub const DIFFICULT: usize = 10;
}

#[cfg(feature = "ntrup1013")]
pub mod params1013 {
    pub const P: usize = 1013;
    pub const Q: usize = 7177;
    pub const W: usize = 448;
    pub const Q12: usize = (Q - 1) / 2;
    pub const R3_BYTES: usize = (P + 3) / 4;
    pub const RQ_BYTES: usize = P * 2;
    pub const PUBLICKEYS_BYTES: usize = RQ_BYTES;
    pub const SECRETKEYS_BYTES: usize = R3_BYTES * 2;
    pub const DIFFICULT: usize = 12;
}

#[cfg(feature = "ntrup1277")]
pub mod params1277 {
    pub const P: usize = 1277;
    pub const Q: usize = 7879;
    pub const W: usize = 492;
    pub const Q12: usize = (Q - 1) / 2;
    pub const R3_BYTES: usize = (P + 3) / 4;
    pub const RQ_BYTES: usize = P * 2;
    pub const PUBLICKEYS_BYTES: usize = RQ_BYTES;
    pub const SECRETKEYS_BYTES: usize = R3_BYTES * 2;
    pub const DIFFICULT: usize = 14;
}
