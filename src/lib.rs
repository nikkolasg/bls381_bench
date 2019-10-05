#![feature(test)]
#[cfg(test)]
mod tests {
    use paired::bls12_381::{Bls12, Fr, G1Affine, G1Compressed, G2Compressed, G1, G2};
    use paired::{CurveProjective, EncodedPoint, Engine};
    use rand::{Rand, Rng, SeedableRng, XorShiftRng};

    extern crate test;
    use test::Bencher;

    #[test]
    fn stats() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let g1: G1 = G1::rand(&mut rng);
        let g1buff = G1Compressed::from_affine(g1.into_affine());
        let g2: G2 = G2::rand(&mut rng);
        let g2buff = G2Compressed::from_affine(g2.into_affine());
        println!("G1 point: {} bytes", g1buff.as_ref().len());
        println!("G2 point: {} bytes", g2buff.as_ref().len());
    }

    #[bench]
    fn g2_addition(b: &mut Bencher) {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        b.iter(|| {
            let mut p1: G2 = G2::rand(&mut rng);
            let p2: G2 = G2::rand(&mut rng);
            p1.add_assign(&p2);
        });
    }

    #[bench]
    fn g1_addition(b: &mut Bencher) {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        b.iter(|| {
            let mut p1: G1 = G1::rand(&mut rng);
            let p2: G1 = G1::rand(&mut rng);
            p1.add_assign(&p2);
        });
    }

    #[bench]
    fn g1signature(b: &mut Bencher) {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let msg: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
        b.iter(|| {
            // g1 signature, g2 public key
            // e(sig,g2) == e(H(m), pub)
            // e(H(m)^x,g2) == e(H(m), g2^x)
            // e(g1^s^x, g2) == e(g1^s, g2^x)
            // T ^ s*x    == T^s*x
            let g2: G2 = G2::rand(&mut rng);
            let hashed: G1 = G1::hash(&msg);
            let sk: Fr = Fr::rand(&mut rng);
            let mut sig = hashed;
            sig.mul_assign(sk);
            let mut pk: G2 = g2;
            pk.mul_assign(sk);
            let left = Bls12::pairing(sig, g2);
            let right = Bls12::pairing(hashed, pk);

            assert_eq!(left, right);
        });
    }

    #[bench]
    fn g2signature(b: &mut Bencher) {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let msg: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
        b.iter(|| {
            // g2 signature, g1 public key
            // e(g1,sig) == e(pub,H(m))
            // e(g1, H(m)^x) == e(g1^x,H(m))
            // e(g1, g2^s^x) == e(g1^x, g2^s)
            // T ^ s*x    == T^s*x
            let g1: G1 = G1::rand(&mut rng);
            let hashed: G2 = G2::hash(&msg);
            let sk: Fr = Fr::rand(&mut rng);
            let mut sig = hashed;
            sig.mul_assign(sk);
            let mut pk: G1 = g1;
            pk.mul_assign(sk);
            let left = Bls12::pairing(g1, sig);
            let right = Bls12::pairing(pk, hashed);
            assert_eq!(left, right);
        });
    }
}
