use bicycl::{CL_HSMqk, Mpz, RandGen};
use bls12_381::Scalar;
use criterion::{criterion_group, criterion_main, Criterion};

use curv::arithmetic::Converter;
use curv::BigInt;
use ff::Field;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use threshold_bbsp::MODULUS;
use threshold_bbsp::*;

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

    let key_msg = n_out_of_n::setbbsplus::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    let sign_msg =
        n_out_of_n::setbbsplus::Sign::sign(&cl, n, l, &mut rng, &mut scalr_rng, &key_msg, &msg, &q);
    group.bench_function(
        "Benchmarking client-side of 10 out of 10 parties SET-BBS+",
        |b| {
            b.iter(|| {
                n_out_of_n::setbbsplus::Sign::client(&cl, &sign_msg, &msg, l);
            })
        },
    );

    let key_msg = n_out_of_n::wmc24::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    let sign_msg =
        n_out_of_n::wmc24::Sign::sign(&cl, n, l, &mut rng, &mut scalr_rng, &key_msg, &msg);
    group.bench_function(
        "Benchmarking client-side of 10 out of 10 parties WMC24",
        |b| {
            b.iter(|| {
                n_out_of_n::wmc24::Sign::client(&cl, &sign_msg);
            })
        },
    );

    let n = 15;
    let t = 10;

    let key_msg = t_out_of_n::setbbsplus::KeyGen::keygen(&cl, n, t, l, &mut rng, &mut scalr_rng);
    let sign_msg =
        t_out_of_n::setbbsplus::Sign::sign(&cl, t, l, &mut rng, &mut scalr_rng, &key_msg, &msg, &q);
    group.bench_function(
        "Benchmarking client-side of 10 out of 15 parties SET-BBS+",
        |b| {
            b.iter(|| {
                t_out_of_n::setbbsplus::Sign::client(&cl, &sign_msg, &msg, l);
            })
        },
    );

    let key_msg = t_out_of_n::wmc24::KeyGen::keygen(&cl, n, t, l, &mut rng, &mut scalr_rng);
    let sign_msg =
        t_out_of_n::wmc24::Sign::sign(&cl, t, l, &mut rng, &mut scalr_rng, &key_msg, &msg);
    group.bench_function(
        "Benchmarking client-side of 10 out of 15 parties WMC24",
        |b| {
            b.iter(|| {
                t_out_of_n::wmc24::Sign::client(&cl, &sign_msg);
            })
        },
    );

    // let n = 20;

    // let key_msg = n_out_of_n::sebbsplus::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    // group.bench_function("Benchmarking 20 parties signing phase of SET-BBS+", |b| {
    //     b.iter(|| {
    //         let _ = n_out_of_n::sebbsplus::Sign::sign(
    //             &cl,
    //             n,
    //             l,
    //             &mut rng,
    //             &mut scalr_rng,
    //             &key_msg,
    //             &msg,
    //             &q,
    //         );
    //     })
    // });

    // let key_msg = n_out_of_n::wmc24::KeyGen::keygen(&cl, n, l, &mut rng, &mut scalr_rng);
    // group.bench_function("Benchmarking 20 parties signing phase of WMC24", |b| {
    //     b.iter(|| {
    //         let _ =
    //             n_out_of_n::wmc24::Sign::sign(&cl, n, l, &mut rng, &mut scalr_rng, &key_msg, &msg);
    //     })
    // });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
