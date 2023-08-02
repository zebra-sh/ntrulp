use crate::{
    config::params::StartParams,
    key::{private::NtruPrimePrivKey, public::NtruPrimePubKey},
    poly::poly::NtruIntPoly,
};

#[derive(Debug)]
pub struct NtruPrimeKeyPair {
    pub private: NtruPrimePrivKey,
    pub public: NtruPrimePubKey,
    params: StartParams,
}

impl NtruPrimeKeyPair {
    pub fn from() {}

    pub fn gen(params: StartParams) -> Self {
        let g = NtruIntPoly::random(params.0 as usize);
        let f = NtruIntPoly::fisher_yates_shuffle(params.0 as usize);

        NtruPrimeKeyPair::gen_from_seed(params, g, f)
    }

    pub fn gen_from_seed(params: StartParams, g: NtruIntPoly, f: NtruIntPoly) -> Self {
        let (_, q, _, inv_3) = params;
        let g_inv = loop {
            match g.get_inv_poly(q) {
                Some(inv) => {
                    break inv;
                }
                None => continue,
            }
        };
        let priv_key = NtruPrimePrivKey { f, g_inv };
        let mut pub_key = NtruPrimePubKey {
            h: NtruIntPoly::empty(),
        };
        let f_inv = loop {
            match priv_key.f.get_inv_poly(q) {
                Some(inv) => {
                    break inv;
                }
                None => continue,
            }
        };

        pub_key.h.mult_poly(&g, &f_inv, q);
        pub_key.h.mult_mod(inv_3 as u64, q as u64);

        NtruPrimeKeyPair {
            params,
            private: priv_key,
            public: pub_key,
        }
    }

    pub fn verify(&self) -> bool {
        let mut a = NtruIntPoly::from_zero(self.params.0 as usize);
        let mut b = NtruIntPoly::from_zero(self.params.0 as usize);

        a.mult_poly(&self.public.h, &self.private.f, self.params.1);
        a.mult_mod(3, self.params.1 as u64);
        b.mult_poly(&a, &self.private.g_inv, self.params.1);

        b.equals_one()
    }
}

#[cfg(test)]
mod tests {
    use crate::config::params::StartParams;
    use crate::key::pair::NtruPrimeKeyPair;
    use crate::poly::poly::NtruIntPoly;

    #[test]
    fn test_key_pair_gen() {
        use crate::config::params::SNTRUP761;

        let pair = NtruPrimeKeyPair::gen(SNTRUP761);

        assert!(pair.private.f.n == SNTRUP761.0 as usize);
        assert!(pair.private.f.coeffs.contains(&0));
        assert!(pair.private.f.coeffs.contains(&1));
        assert!(pair.private.f.coeffs.contains(&2));
    }

    #[test]
    fn test_valid() {
        let params: StartParams = (739, 9829, 204, 6553);
        let pair = NtruPrimeKeyPair::gen(params);

        pair.verify();
    }

    #[test]
    fn test_verify_and_big_pair() {
        let params: StartParams = (739, 9829, 204, 6553);
        let mut seed_f = NtruIntPoly::empty();
        let mut seed_g = NtruIntPoly::empty();

        seed_f.coeffs = vec![
            1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 2, 2, 0, 2, 2, 0, 2, 0, 1, 1, 0, 0, 0, 0, 1, 1, 2, 2,
            1, 0, 1, 1, 1, 1, 0, 1, 2, 1, 1, 2, 0, 0, 2, 1, 2, 0, 2, 1, 2, 0, 0, 2, 0, 2, 0, 2, 0,
            0, 0, 1, 0, 2, 1, 2, 0, 2, 2, 0, 0, 2, 0, 2, 0, 1, 1, 2, 0, 1, 0, 0, 2, 1, 0, 2, 2, 0,
            2, 0, 1, 0, 2, 2, 0, 0, 2, 2, 1, 1, 0, 0, 0, 0, 1, 2, 2, 2, 2, 1, 2, 1, 0, 1, 0, 0, 0,
            2, 0, 0, 2, 0, 2, 1, 0, 0, 0, 0, 0, 2, 2, 2, 2, 1, 1, 2, 1, 2, 2, 0, 0, 1, 0, 0, 0, 0,
            0, 0, 1, 0, 2, 0, 0, 2, 2, 2, 0, 0, 0, 0, 0, 2, 2, 0, 0, 1, 1, 1, 2, 2, 0, 2, 1, 0, 2,
            2, 0, 0, 0, 0, 1, 0, 2, 2, 0, 1, 2, 0, 1, 2, 0, 0, 0, 1, 2, 1, 0, 1, 0, 1, 1, 2, 0, 2,
            2, 0, 2, 0, 0, 1, 2, 2, 2, 1, 1, 0, 2, 0, 0, 0, 2, 2, 0, 2, 2, 0, 1, 0, 0, 0, 0, 0, 1,
            0, 2, 0, 0, 2, 1, 2, 0, 0, 0, 1, 0, 0, 1, 2, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0,
            2, 2, 1, 1, 0, 1, 2, 0, 0, 0, 1, 2, 1, 2, 1, 2, 2, 2, 2, 0, 1, 0, 1, 1, 1, 0, 2, 0, 1,
            1, 2, 0, 1, 2, 1, 0, 0, 0, 0, 2, 2, 1, 2, 2, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 2, 0, 0, 0,
            0, 0, 0, 0, 1, 0, 0, 2, 2, 1, 1, 1, 2, 2, 2, 2, 0, 1, 2, 0, 2, 0, 1, 0, 0, 0, 0, 2, 0,
            1, 2, 0, 2, 0, 2, 0, 1, 0, 1, 1, 1, 1, 0, 0, 2, 0, 1, 1, 0, 2, 1, 1, 1, 1, 1, 1, 2, 1,
            1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 2, 0, 0, 2, 2, 0, 1, 0, 2, 1, 2, 2, 1, 2, 0, 0,
            1, 0, 0, 0, 2, 1, 0, 2, 2, 0, 0, 0, 2, 2, 2, 2, 0, 1, 2, 1, 1, 1, 0, 2, 1, 2, 1, 0, 0,
            0, 2, 2, 0, 0, 2, 1, 0, 0, 2, 1, 0, 1, 1, 2, 1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 2, 2, 1, 0,
            1, 0, 2, 0, 0, 2, 2, 2, 0, 2, 0, 0, 0, 1, 1, 0, 0, 0, 2, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1,
            0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 2, 2, 1, 0, 2, 1, 2, 1, 0, 2, 2, 0, 2, 1, 0, 1, 0,
            2, 1, 0, 2, 2, 2, 1, 1, 0, 1, 0, 0, 1, 2, 2, 0, 0, 0, 1, 2, 1, 0, 0, 2, 2, 0, 1, 0, 0,
            0, 1, 1, 0, 2, 1, 0, 1, 0, 1, 0, 2, 0, 2, 1, 0, 0, 2, 0, 2, 2, 0, 0, 1, 0, 1, 0, 1, 0,
            2, 1, 0, 2, 0, 2, 0, 2, 2, 0, 0, 2, 2, 1, 0, 0, 0, 2, 1, 0, 1, 1, 0, 2, 0, 0, 0, 1, 0,
            1, 0, 0, 0, 0, 1, 2, 1, 0, 1, 1, 2, 1, 2, 1, 0, 1, 2, 0, 2, 1, 0, 2, 0, 1, 0, 1, 1, 2,
            0, 2, 2, 2, 0, 1, 0, 0, 0, 2, 0, 0, 2, 0, 0, 0, 2, 0, 0, 2, 0, 2, 2, 2, 0, 0, 2, 2, 2,
            0, 0, 0, 0, 0, 0, 1, 0, 1, 2, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 0, 0, 1, 0, 0, 2, 0, 1, 2,
            2, 0, 2, 2, 0, 1, 2, 1, 0, 1, 2, 0, 0, 0, 2, 1, 2, 1, 2, 1, 1, 2, 1, 1, 0, 0, 0, 2, 0,
            0, 1, 0, 1, 1, 0, 0, 0, 1, 2, 0, 1, 0, 0,
        ];
        seed_f.n = seed_f.coeffs.len();

        seed_g.coeffs = vec![
            2, 2, 2, 2, 1, 0, 1, 2, 0, 0, 1, 1, 1, 2, 0, 0, 0, 1, 1, 2, 1, 1, 2, 2, 0, 1, 2, 2, 0,
            0, 2, 0, 1, 0, 1, 2, 1, 1, 0, 1, 1, 2, 1, 0, 2, 1, 0, 0, 0, 1, 0, 1, 0, 1, 2, 1, 1, 0,
            1, 1, 0, 2, 2, 1, 2, 0, 1, 0, 0, 0, 0, 2, 0, 2, 1, 2, 2, 1, 0, 0, 2, 2, 1, 0, 1, 0, 1,
            0, 1, 2, 2, 0, 0, 1, 0, 0, 2, 1, 2, 2, 0, 1, 0, 2, 1, 1, 0, 0, 1, 2, 1, 1, 1, 0, 0, 2,
            1, 1, 1, 2, 2, 2, 1, 0, 1, 0, 2, 1, 2, 0, 0, 1, 1, 1, 0, 1, 0, 2, 2, 0, 2, 2, 1, 2, 0,
            0, 2, 0, 0, 2, 0, 0, 0, 1, 2, 1, 0, 2, 0, 1, 0, 0, 0, 1, 1, 2, 1, 1, 1, 2, 0, 2, 2, 1,
            2, 1, 0, 0, 0, 2, 0, 2, 1, 0, 0, 0, 1, 2, 1, 0, 0, 0, 2, 2, 0, 0, 2, 2, 1, 0, 0, 2, 0,
            1, 1, 2, 2, 1, 2, 0, 2, 0, 1, 0, 0, 1, 2, 0, 0, 2, 1, 2, 1, 2, 1, 2, 2, 0, 2, 1, 2, 1,
            0, 1, 2, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 2, 0, 0, 0, 2, 2, 1, 2, 2, 2, 0, 1,
            1, 1, 0, 2, 1, 1, 1, 2, 1, 0, 2, 2, 0, 2, 1, 2, 0, 0, 0, 1, 2, 0, 0, 2, 0, 2, 1, 1, 1,
            0, 1, 2, 0, 1, 0, 0, 0, 2, 2, 2, 0, 2, 1, 0, 0, 0, 0, 2, 2, 1, 2, 0, 2, 0, 2, 2, 2, 2,
            0, 2, 0, 2, 1, 0, 1, 0, 0, 1, 0, 2, 1, 2, 0, 2, 2, 2, 0, 2, 2, 2, 2, 2, 0, 2, 2, 0, 0,
            0, 1, 1, 0, 2, 2, 2, 2, 1, 1, 2, 2, 0, 0, 0, 2, 1, 0, 0, 0, 1, 0, 1, 1, 2, 1, 1, 2, 1,
            0, 2, 0, 2, 0, 1, 2, 1, 2, 0, 2, 2, 0, 0, 2, 0, 1, 2, 1, 2, 0, 2, 2, 2, 0, 1, 0, 2, 2,
            0, 2, 0, 0, 2, 1, 2, 1, 1, 0, 1, 1, 0, 1, 2, 1, 2, 1, 0, 2, 1, 1, 2, 2, 2, 1, 2, 1, 2,
            2, 0, 2, 1, 0, 1, 1, 0, 2, 2, 2, 2, 1, 0, 2, 1, 2, 1, 1, 2, 0, 2, 1, 0, 1, 2, 0, 1, 0,
            0, 2, 0, 2, 1, 2, 2, 2, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 2, 2, 1, 0, 2, 2, 1, 0, 1, 0, 2,
            0, 2, 2, 2, 0, 1, 2, 0, 1, 2, 1, 0, 1, 1, 1, 1, 2, 1, 1, 2, 0, 2, 2, 1, 1, 1, 2, 0, 1,
            2, 2, 2, 0, 1, 0, 2, 2, 0, 2, 2, 2, 2, 0, 1, 0, 2, 0, 1, 1, 0, 0, 0, 2, 1, 1, 1, 2, 0,
            2, 1, 2, 0, 1, 1, 0, 1, 2, 2, 1, 2, 0, 1, 2, 1, 0, 2, 0, 0, 1, 0, 1, 0, 1, 2, 1, 2, 0,
            0, 0, 1, 2, 1, 0, 0, 0, 2, 2, 2, 0, 0, 0, 2, 1, 2, 1, 2, 0, 2, 0, 0, 2, 1, 1, 0, 1, 0,
            2, 0, 1, 1, 2, 0, 1, 0, 1, 1, 1, 2, 2, 0, 0, 1, 2, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1,
            1, 2, 0, 2, 2, 1, 1, 0, 0, 0, 2, 1, 1, 1, 2, 0, 0, 2, 1, 0, 2, 2, 2, 0, 0, 0, 0, 0, 1,
            0, 1, 0, 1, 1, 0, 0, 2, 2, 2, 2, 2, 2, 0, 1, 2, 0, 1, 0, 2, 0, 2, 2, 2, 0, 2, 1, 0, 0,
            0, 1, 1, 1, 0, 0, 0, 2, 1, 1, 2, 1, 0, 1, 2, 1, 0, 2, 1, 1, 1, 0, 2, 1, 0, 0, 0, 2, 1,
            1, 1, 2, 1, 2, 2, 1, 1, 0, 2, 2, 1, 1, 1,
        ];
        seed_g.n = seed_g.coeffs.len();

        let key_pair = NtruPrimeKeyPair::gen_from_seed(params, seed_g, seed_f);

        assert!(
            key_pair.public.h.coeffs
                == [
                    1242, 9668, 9307, 516, 2172, 8165, 1289, 2396, 4015, 9046, 5505, 8583, 2770,
                    3537, 2582, 1512, 169, 9080, 243, 8780, 6280, 1199, 2958, 8050, 6292, 6670,
                    7784, 690, 1686, 8332, 8526, 9169, 6745, 477, 4205, 2108, 1061, 6367, 6743,
                    3435, 9298, 5917, 518, 6459, 0, 9521, 3517, 6213, 6388, 8955, 5774, 6551, 3984,
                    2360, 2931, 2226, 8781, 8120, 5659, 9688, 4436, 1016, 5624, 6374, 5743, 3741,
                    466, 4065, 5486, 4529, 8148, 3946, 6691, 1163, 3899, 5010, 5343, 7234, 5726,
                    9039, 2096, 1641, 5135, 8717, 3186, 2613, 2932, 9745, 8140, 57, 5844, 7528,
                    2658, 8166, 1659, 4444, 9095, 401, 7004, 2083, 5911, 4438, 9484, 5795, 7162,
                    1606, 2980, 6507, 7978, 4388, 9581, 5173, 3614, 9365, 643, 2809, 1187, 2580,
                    1107, 4066, 713, 1786, 9171, 6813, 829, 7731, 4234, 9285, 8696, 9439, 9529,
                    8782, 8264, 5396, 9203, 8533, 5025, 6988, 8855, 7074, 1870, 8237, 4863, 8787,
                    4504, 5493, 2656, 3442, 8236, 1793, 2415, 4356, 2383, 2145, 5194, 8336, 2910,
                    6895, 7093, 8695, 2064, 7927, 5229, 3933, 955, 7512, 1946, 6083, 994, 3221,
                    1135, 3118, 9326, 8649, 5821, 73, 2658, 5154, 3140, 583, 7012, 5456, 5790,
                    1362, 6126, 1240, 482, 4894, 6146, 8435, 1566, 4604, 5879, 901, 8290, 4782,
                    3508, 2352, 2575, 2969, 8905, 9791, 7477, 9555, 3890, 4367, 4387, 7149, 4203,
                    4457, 1253, 6317, 893, 5484, 1636, 9574, 298, 9784, 5851, 1660, 8757, 5987,
                    5712, 4049, 1718, 8154, 6581, 7445, 8987, 3175, 2874, 2689, 2441, 3895, 2575,
                    5602, 1192, 9185, 5353, 3901, 7200, 9761, 7791, 4758, 7666, 1681, 9114, 805,
                    1116, 5648, 8100, 1806, 2062, 6708, 1184, 5563, 4017, 7443, 4959, 1730, 7721,
                    3328, 6612, 3900, 3564, 6142, 3461, 3584, 6176, 449, 9085, 9248, 4454, 2624,
                    8332, 5220, 4973, 5461, 9431, 1513, 7659, 8901, 9385, 340, 4193, 9506, 7267,
                    8498, 6528, 4210, 3774, 5792, 4338, 3612, 8450, 6460, 2250, 2560, 6190, 9489,
                    9159, 8730, 9034, 7618, 6362, 8398, 952, 9077, 745, 7999, 6478, 4708, 3067,
                    8359, 8128, 6484, 2986, 1293, 1427, 4539, 5103, 863, 8863, 6809, 2456, 4310,
                    279, 642, 2971, 5245, 2353, 3935, 6746, 6788, 4260, 8806, 3233, 3435, 575,
                    7886, 7158, 9117, 4437, 1809, 4105, 880, 373, 5008, 33, 8139, 7425, 2258, 8669,
                    4917, 4638, 8833, 9320, 6162, 3829, 9083, 417, 8203, 5352, 4098, 6163, 7199,
                    1684, 9760, 816, 6781, 7405, 8051, 5551, 2908, 950, 4003, 4777, 5941, 8488,
                    3576, 9500, 2000, 2214, 4980, 7356, 7804, 421, 8740, 59, 9426, 8108, 5963,
                    5559, 9112, 4536, 6345, 2608, 7569, 3714, 3047, 4646, 5998, 4338, 6076, 9296,
                    6060, 8825, 2190, 2610, 1763, 1994, 2212, 6701, 2247, 4823, 4673, 3101, 6348,
                    4115, 7271, 3329, 3260, 3560, 3974, 2712, 7753, 3732, 273, 8986, 7759, 1321,
                    6630, 4061, 765, 9793, 475, 9596, 8105, 5382, 5291, 4980, 704, 1749, 7639,
                    7802, 1247, 7701, 2254, 5881, 7202, 9262, 8718, 4473, 1268, 1034, 3447, 3130,
                    8216, 8535, 4829, 5731, 4909, 9608, 4245, 1902, 1253, 3414, 1517, 6108, 1308,
                    2462, 4478, 5736, 8755, 6739, 4209, 8937, 1958, 1473, 2541, 3048, 4969, 4092,
                    2265, 425, 3710, 367, 4151, 3313, 4098, 5417, 2412, 8942, 7970, 843, 2121,
                    9484, 705, 293, 7126, 8845, 5185, 8542, 8899, 2678, 1066, 5002, 961, 9756,
                    5772, 5717, 6284, 568, 4602, 5156, 9494, 6195, 1931, 5727, 4985, 7082, 4729,
                    6217, 3324, 8786, 7089, 2939, 4370, 9148, 6845, 4289, 9765, 1028, 8373, 8020,
                    5530, 3953, 3979, 8359, 5303, 1248, 9000, 4788, 6307, 8747, 2170, 8916, 9561,
                    6451, 8973, 8040, 8951, 5919, 6190, 8822, 3429, 1976, 1957, 5804, 9145, 549,
                    2602, 7028, 3148, 1998, 9480, 8552, 502, 5149, 988, 8346, 7221, 7771, 9462,
                    8643, 7423, 4590, 5091, 5136, 6934, 8886, 6036, 4134, 6914, 6241, 7607, 571,
                    7389, 8372, 5836, 6745, 4119, 4591, 332, 5537, 4873, 7607, 4488, 6185, 4837,
                    7240, 757, 6411, 3543, 7253, 990, 854, 8861, 6850, 9440, 3716, 7647, 7945,
                    5256, 7328, 5544, 5156, 92, 2589, 84, 8153, 8681, 3213, 1291, 8604, 7343, 5890,
                    8648, 6403, 5003, 182, 2330, 3762, 9749, 5595, 7813, 3855, 9703, 5105, 4564,
                    344, 4964, 7395, 2543, 9655, 5778, 9019, 2361, 1766, 7254, 6508, 3546, 9202,
                    7673, 6014, 386, 3513, 9250, 5072, 375, 7432, 356, 8117, 9388, 1076, 6435,
                    1810, 4916, 5712, 4629, 7893, 9197, 8077, 6579, 8305, 5758, 3472, 2435, 9634,
                    7706, 9467, 80, 7156, 7896, 2377, 150, 5203, 1102, 1249, 4120, 4821, 6556,
                    3696, 6351, 7369, 5244, 8879, 4690, 3987, 1499, 6511, 249, 5502, 566, 5833,
                    2252, 610, 1058, 536, 3289, 5625, 263, 5364, 8436, 5115, 5172, 1213, 714, 293,
                    5273, 1349, 3185, 9210, 2843, 8205, 651, 2161, 6462, 2628, 6010, 597, 5275,
                    1851, 7223, 8068, 4951, 4486, 5931, 1766,
                ]
        );
        assert!(
            key_pair.private.g_inv.coeffs
                == [
                    1773, 7934, 8684, 1979, 5078, 6989, 7860, 7956, 7113, 9715, 8324, 5768, 4240,
                    8617, 7294, 2304, 6495, 5069, 3606, 3765, 718, 7825, 4222, 5655, 6083, 10,
                    2976, 1344, 9457, 469, 4342, 7040, 7503, 8509, 9096, 3405, 3287, 7558, 8018,
                    834, 2208, 4085, 1267, 7410, 3446, 1460, 5025, 1967, 6753, 3625, 8925, 6503,
                    5506, 5838, 9588, 439, 4161, 1509, 6068, 743, 47, 423, 1335, 7607, 2259, 2008,
                    8389, 5264, 4041, 1796, 9421, 2424, 420, 9079, 4680, 5567, 6972, 2963, 2731,
                    4033, 1532, 599, 1029, 4089, 4680, 8691, 1961, 1963, 8332, 8364, 1505, 7057,
                    7473, 4999, 6432, 4265, 5503, 3939, 58, 318, 1097, 9324, 6555, 2215, 587, 1975,
                    2353, 506, 6385, 1723, 4742, 819, 7312, 5353, 1165, 858, 3562, 660, 6253, 1393,
                    8543, 7498, 8658, 7431, 4419, 5285, 3722, 2100, 2422, 5829, 9507, 5876, 1697,
                    8455, 7006, 1324, 576, 8199, 306, 25, 5613, 482, 6418, 6907, 1753, 3282, 3308,
                    3107, 3483, 9767, 2981, 2129, 3253, 1156, 7807, 9800, 4370, 4000, 5517, 3902,
                    3176, 4044, 6975, 8743, 1416, 3959, 2794, 2824, 1941, 7190, 3102, 2655, 8972,
                    307, 1179, 3989, 4958, 1029, 3600, 3095, 4682, 2725, 7879, 5262, 4369, 2362,
                    4527, 9313, 3720, 3484, 662, 5223, 6237, 9060, 6094, 6875, 9617, 7469, 3324,
                    5133, 1776, 1512, 4407, 8910, 9613, 2016, 6309, 4909, 3303, 6854, 3297, 4466,
                    1728, 8944, 4391, 5595, 7858, 9175, 5111, 9773, 5940, 6752, 3301, 3901, 3182,
                    3741, 5424, 5881, 9138, 3360, 7032, 9306, 6297, 3434, 5974, 1078, 8314, 6683,
                    3913, 118, 2324, 5893, 5315, 3775, 7301, 4133, 2197, 8047, 9119, 4407, 6583,
                    6211, 853, 3471, 5541, 8143, 4670, 5367, 9620, 1154, 9020, 7476, 8129, 8137,
                    9260, 2683, 8505, 5113, 9710, 4244, 5459, 3718, 6344, 2828, 4309, 4213, 3413,
                    5421, 6922, 4912, 7269, 4688, 6299, 4831, 2638, 3693, 8947, 3177, 1772, 8451,
                    6417, 3516, 6478, 6366, 8575, 914, 3224, 1986, 5125, 4583, 8845, 7082, 1175,
                    6720, 9568, 825, 1839, 614, 8139, 2383, 6578, 7413, 9439, 4082, 5423, 1660,
                    3986, 2177, 9134, 8352, 2513, 7950, 8467, 4964, 5294, 4171, 5073, 5564, 8442,
                    1141, 8556, 1865, 261, 404, 6850, 6828, 6407, 3422, 2103, 6205, 417, 2754,
                    5813, 2853, 550, 6045, 4924, 3418, 2339, 1622, 9352, 3787, 2212, 2721, 6410,
                    3582, 2894, 439, 1956, 3031, 998, 6917, 4069, 966, 2649, 2761, 2794, 5292,
                    3794, 1069, 5441, 6584, 7556, 3432, 3665, 260, 1627, 4065, 1339, 3529, 6286,
                    7005, 2053, 6448, 8186, 8783, 3247, 1448, 8446, 3177, 6380, 7686, 9533, 8280,
                    5771, 7355, 6402, 8755, 3055, 5306, 1162, 248, 2279, 1418, 9755, 123, 8214,
                    2626, 6842, 4701, 5046, 447, 1433, 181, 7817, 2257, 7487, 5059, 5614, 555,
                    2126, 6673, 4965, 6444, 7921, 8009, 9312, 8513, 2239, 3639, 2551, 6087, 7646,
                    1889, 7811, 5767, 8936, 6272, 2770, 9467, 4138, 8386, 7928, 1318, 500, 7504,
                    2227, 119, 238, 8736, 2159, 4325, 2465, 7114, 1472, 7459, 1592, 2855, 9052,
                    3423, 1297, 7586, 6638, 9790, 2860, 4252, 1114, 190, 7682, 134, 3849, 2517,
                    7559, 8533, 8232, 1102, 5305, 3741, 8038, 1006, 1628, 6499, 300, 7456, 4065,
                    1951, 1967, 680, 7392, 5707, 8880, 3453, 3231, 6184, 1419, 5787, 7474, 8579,
                    3571, 5118, 8708, 8148, 4548, 1420, 5874, 9082, 2244, 9136, 1955, 591, 7750,
                    4611, 2552, 5350, 6623, 276, 7688, 5638, 6025, 5711, 8553, 8084, 651, 4179,
                    853, 6772, 5788, 306, 5847, 5399, 2208, 2890, 4259, 3714, 3784, 2550, 7543,
                    9523, 9528, 541, 1269, 3996, 3145, 4569, 4318, 3176, 1709, 2637, 6840, 1572,
                    962, 8853, 9229, 6202, 3851, 155, 2330, 1703, 1104, 732, 6768, 6485, 9438, 518,
                    3653, 7558, 4470, 4014, 6684, 933, 3379, 8905, 3640, 5250, 4187, 5497, 6611,
                    982, 1378, 7013, 4164, 7698, 4368, 2001, 7822, 8810, 710, 5646, 9550, 9255,
                    6521, 4624, 5934, 3537, 6251, 7249, 5392, 1484, 1331, 411, 1314, 1606, 6130,
                    3587, 1968, 8972, 534, 2020, 9068, 4577, 8576, 3292, 2870, 4207, 5970, 1977,
                    1170, 483, 3142, 735, 1669, 6994, 3820, 3898, 8649, 8383, 4768, 8344, 729,
                    1181, 2522, 4247, 6562, 2029, 5370, 6733, 7905, 1062, 2980, 7572, 3173, 2229,
                    8377, 8141, 9662, 2420, 9691, 8310, 3926, 8958, 1786, 8706, 6492, 5814, 9656,
                    7874, 8075, 1226, 5702, 7489, 7452, 8205, 1709, 4621, 2124, 6844, 3090, 9255,
                    9301, 3163, 7459, 7712, 690, 6558, 8706, 8245, 1368, 7813, 7166, 1637, 4064,
                    297, 5859, 7484, 9222, 5237, 1253, 5984, 1393, 9555, 7929, 9608, 1762, 2065,
                    174, 2442, 5294, 7008, 8199, 2346, 4465, 8056, 8763, 8699, 859, 5485, 3338,
                    2269, 6343, 7212, 7880, 7765, 5606, 7251, 6113, 3962, 908, 946, 9308, 7859,
                    3459, 7681, 1357, 4052, 5352, 9745, 825, 6334, 8732, 9791, 1806, 9151, 5540,
                    256, 4875, 1429, 9535, 3152, 7390,
                ]
        );

        assert!(
            key_pair.private.f.coeffs
                == [
                    1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 2, 2, 0, 2, 2, 0, 2, 0, 1, 1, 0, 0, 0, 0, 1,
                    1, 2, 2, 1, 0, 1, 1, 1, 1, 0, 1, 2, 1, 1, 2, 0, 0, 2, 1, 2, 0, 2, 1, 2, 0, 0,
                    2, 0, 2, 0, 2, 0, 0, 0, 1, 0, 2, 1, 2, 0, 2, 2, 0, 0, 2, 0, 2, 0, 1, 1, 2, 0,
                    1, 0, 0, 2, 1, 0, 2, 2, 0, 2, 0, 1, 0, 2, 2, 0, 0, 2, 2, 1, 1, 0, 0, 0, 0, 1,
                    2, 2, 2, 2, 1, 2, 1, 0, 1, 0, 0, 0, 2, 0, 0, 2, 0, 2, 1, 0, 0, 0, 0, 0, 2, 2,
                    2, 2, 1, 1, 2, 1, 2, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 0, 2, 2, 2, 0,
                    0, 0, 0, 0, 2, 2, 0, 0, 1, 1, 1, 2, 2, 0, 2, 1, 0, 2, 2, 0, 0, 0, 0, 1, 0, 2,
                    2, 0, 1, 2, 0, 1, 2, 0, 0, 0, 1, 2, 1, 0, 1, 0, 1, 1, 2, 0, 2, 2, 0, 2, 0, 0,
                    1, 2, 2, 2, 1, 1, 0, 2, 0, 0, 0, 2, 2, 0, 2, 2, 0, 1, 0, 0, 0, 0, 0, 1, 0, 2,
                    0, 0, 2, 1, 2, 0, 0, 0, 1, 0, 0, 1, 2, 0, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0,
                    0, 2, 2, 1, 1, 0, 1, 2, 0, 0, 0, 1, 2, 1, 2, 1, 2, 2, 2, 2, 0, 1, 0, 1, 1, 1,
                    0, 2, 0, 1, 1, 2, 0, 1, 2, 1, 0, 0, 0, 0, 2, 2, 1, 2, 2, 0, 0, 1, 0, 1, 0, 0,
                    1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 2, 2, 1, 1, 1, 2, 2, 2, 2, 0, 1, 2,
                    0, 2, 0, 1, 0, 0, 0, 0, 2, 0, 1, 2, 0, 2, 0, 2, 0, 1, 0, 1, 1, 1, 1, 0, 0, 2,
                    0, 1, 1, 0, 2, 1, 1, 1, 1, 1, 1, 2, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0,
                    2, 0, 0, 2, 2, 0, 1, 0, 2, 1, 2, 2, 1, 2, 0, 0, 1, 0, 0, 0, 2, 1, 0, 2, 2, 0,
                    0, 0, 2, 2, 2, 2, 0, 1, 2, 1, 1, 1, 0, 2, 1, 2, 1, 0, 0, 0, 2, 2, 0, 0, 2, 1,
                    0, 0, 2, 1, 0, 1, 1, 2, 1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 2, 2, 1, 0, 1, 0, 2, 0,
                    0, 2, 2, 2, 0, 2, 0, 0, 0, 1, 1, 0, 0, 0, 2, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0,
                    0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 2, 2, 1, 0, 2, 1, 2, 1, 0, 2, 2, 0, 2, 1, 0,
                    1, 0, 2, 1, 0, 2, 2, 2, 1, 1, 0, 1, 0, 0, 1, 2, 2, 0, 0, 0, 1, 2, 1, 0, 0, 2,
                    2, 0, 1, 0, 0, 0, 1, 1, 0, 2, 1, 0, 1, 0, 1, 0, 2, 0, 2, 1, 0, 0, 2, 0, 2, 2,
                    0, 0, 1, 0, 1, 0, 1, 0, 2, 1, 0, 2, 0, 2, 0, 2, 2, 0, 0, 2, 2, 1, 0, 0, 0, 2,
                    1, 0, 1, 1, 0, 2, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 2, 1, 0, 1, 1, 2, 1, 2, 1,
                    0, 1, 2, 0, 2, 1, 0, 2, 0, 1, 0, 1, 1, 2, 0, 2, 2, 2, 0, 1, 0, 0, 0, 2, 0, 0,
                    2, 0, 0, 0, 2, 0, 0, 2, 0, 2, 2, 2, 0, 0, 2, 2, 2, 0, 0, 0, 0, 0, 0, 1, 0, 1,
                    2, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 0, 0, 1, 0, 0, 2, 0, 1, 2, 2, 0, 2, 2, 0, 1,
                    2, 1, 0, 1, 2, 0, 0, 0, 2, 1, 2, 1, 2, 1, 1, 2, 1, 1, 0, 0, 0, 2, 0, 0, 1, 0,
                    1, 1, 0, 0, 0, 1, 2, 0, 1, 0, 0,
                ]
        );

        assert!(key_pair.verify());
    }
}
