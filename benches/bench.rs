use bicycl::{CL_HSMqk, Mpz, RandGen};
use bls12_381::Scalar;
use criterion::{criterion_group, criterion_main, Criterion};

use curv::arithmetic::Converter;
use curv::BigInt;
use ff::Field;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use threshold_bbsp::*;
// use threshold_bbsp::wmc24BBSPlus::{ KeyGen, Sign};
use threshold_bbsp::MODULUS;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Threshold BBS+");
    group
        .sample_size(10)
        .sampling_mode(criterion::SamplingMode::Auto); // for slow benchmarks

    let seed: [u8; 32] = [0u8; 32];
    let mut scalr_rng = ChaChaRng::from_seed(seed);

    let mut rng = RandGen::new();
    rng.set_seed(&Mpz::from(&Scalar::random(scalr_rng.clone())));

    let q = Mpz::from_bytes(&BigInt::from_hex(MODULUS).unwrap().to_bytes());
    let cl = CL_HSMqk::with_rand_gen(
        &q,
        1,
        1827,
        &mut rng,
        &(Mpz::from_bytes(&(BigInt::from(1) << 40).to_bytes())),
        false,
    );

    let l = 10;
    let mut msg: Vec<Scalar> = Vec::with_capacity(l);

    for _ in 0..l {
        let tmp = Scalar::random(scalr_rng.clone());
        msg.push(tmp);
    }

    let n = 10;

    // SEBBS+
    group.bench_function("Benchmarking keygen SEBBS+ for 10 parties", |b| {
        b.iter(|| {
            let _ = n_out_of_n::setbbsplus::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
        })
    });

    // WMC24
    group.bench_function("Benchmarking keygen wmc24 for 10 parties", |b| {
        b.iter(|| {
            let _ = n_out_of_n::wmc24::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
        })
    });

    let key_msg = n_out_of_n::setbbsplus::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    group.bench_function("Benchmarking sign SEBBS+ for 10 parties", |b| {
        b.iter(|| {
            let _ = n_out_of_n::setbbsplus::Sign::sign(
                &cl,
                n,
                l,
                &mut rng,
                &mut scalr_rng,
                &key_msg,
                &msg,
                &q,
            );
        })
    });

    let key_msg = n_out_of_n::wmc24::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    group.bench_function("Benchmarking sign wmc24 for 10 parties", |b| {
        b.iter(|| {
            let _ =
                n_out_of_n::wmc24::Sign::sign(&cl, n, l, &mut rng, &mut scalr_rng, &key_msg, &msg);
        })
    });

    let key_msg = n_out_of_n::setbbsplus::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    let sign_msg =
        n_out_of_n::setbbsplus::Sign::sign(&cl, n, l, &mut rng, &mut scalr_rng, &key_msg, &msg, &q);
    group.bench_function("Benchmarking client SEBBS+ for 10 parties", |b| {
        b.iter(|| {
            n_out_of_n::setbbsplus::Sign::client(&cl, &sign_msg, &msg, l);
        })
    });

    let key_msg = n_out_of_n::wmc24::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    let sign_msg =
        n_out_of_n::wmc24::Sign::sign(&cl, n, l, &mut rng, &mut scalr_rng, &key_msg, &msg);
    group.bench_function("Benchmarking client wmc24 for 10 parties", |b| {
        b.iter(|| {
            n_out_of_n::wmc24::Sign::client(&cl, &sign_msg);
        })
    });

    let n = 20;

    // SEBBS+
    group.bench_function("Benchmarking keygen SEBBS+ for 20 parties", |b| {
        b.iter(|| {
            let _ = n_out_of_n::setbbsplus::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
        })
    });

    // WMC24
    group.bench_function("Benchmarking keygen wmc24 for 20 parties", |b| {
        b.iter(|| {
            let _ = n_out_of_n::wmc24::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
        })
    });

    let key_msg = n_out_of_n::setbbsplus::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    group.bench_function("Benchmarking sign SEBBS+ for 20 parties", |b| {
        b.iter(|| {
            let _ = n_out_of_n::setbbsplus::Sign::sign(
                &cl,
                n,
                l,
                &mut rng,
                &mut scalr_rng,
                &key_msg,
                &msg,
                &q,
            );
        })
    });

    let key_msg = n_out_of_n::wmc24::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    group.bench_function("Benchmarking sign wmc24 for 20 parties", |b| {
        b.iter(|| {
            let _ =
                n_out_of_n::wmc24::Sign::sign(&cl, n, l, &mut rng, &mut scalr_rng, &key_msg, &msg);
        })
    });

    let key_msg = n_out_of_n::setbbsplus::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    let sign_msg =
        n_out_of_n::setbbsplus::Sign::sign(&cl, n, l, &mut rng, &mut scalr_rng, &key_msg, &msg, &q);
    group.bench_function("Benchmarking client SEBBS+ for 20 parties", |b| {
        b.iter(|| {
            n_out_of_n::setbbsplus::Sign::client(&cl, &sign_msg, &msg, l);
        })
    });

    let key_msg = n_out_of_n::wmc24::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    let sign_msg =
        n_out_of_n::wmc24::Sign::sign(&cl, n, l, &mut rng, &mut scalr_rng, &key_msg, &msg);
    group.bench_function("Benchmarking client wmc24 for 20 parties", |b| {
        b.iter(|| {
            n_out_of_n::wmc24::Sign::client(&cl, &sign_msg);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
