#pragma once

// Phase B of the Wang-Chen-Ma (WCM) linkable ring signature integration:
// H' and the public-key masking transformation it drives.
//
// --- What WCM actually specifies (cite: Wang, Chen, Ma, "Adding Linkability
// to Ring Signatures with One-Time Signatures", ISC 2019) ---
//
// Generic construction, Section 3.1:
//   Setup:   choose a hash function H : OVK -> P\hat{K}        (abstract)
//   KeyGen:  pk = p\hat{k} (op) H(ovk)                         (op abstract)
//   Sign:    p\hat{k}'_i = pk_i (op)^{-1} H(ovk_s),  i in [N]
//
// Section 4 (concrete instantiation over the Esgin et al. ring signature)
// fixes two DISTINCT hash functions and fixes the abstract group operation
// to be addition in R_q^n:
//   "two hash functions H : {0,1}* -> C  and  H' : {0,1}* -> R_q^n"
//   KeyGen:  pk  = p\hat{k} + H'(ovk)
//   Sign:    p\hat{k}'_i = pk_i - H'(ovk_s)     for every i in [N]
//
// H (the Fiat-Shamir challenge hash into the monomial challenge set C) is
// already implemented as ring_signature::Shake256CToChallenges /
// CanonicalRSignTranscriptEncoder. H' is a SEPARATE random oracle with a
// different domain and a different codomain (R_q^n, the same space as the
// underlying Esgin public key p\hat{k} = Com_ck(0; r) in R_q^n) and MUST NOT
// reuse the challenge hash's state, domain, or output encoding. This file
// implements only H' and the +/- masking it drives; it is used by both the
// (future) LRKeygen and LRSign/LRVerify phases, nowhere else.
//
// --- Implementation choices not mandated by the paper text (flagged) ---
//
// 1. H' is realised as domain-separated SHAKE256 in XOF mode, absorbing a
//    length-prefixed encoding of (domain tag, format version, the
//    commitment parameters n/degree/q, and the OTS public key bytes), then
//    squeezing coefficients via unbiased rejection sampling (the existing
//    sampling::sample_uniform_vector / sample_uniform_coefficient, which
//    rejects over-range candidates instead of reducing mod q). The paper
//    only requires "a hash function ... modeled as a random oracle" with
//    codomain R_q^n; it does not fix an encoding or a sampling algorithm.
//    Binding the commitment parameters (n, degree, q) into the hash input
//    is an implementation choice to keep H'(ovk) outputs computed under
//    different ring-size/parameter profiles from colliding; the paper does
//    not discuss multiple profiles.
// 2. The domain-separation tag strings below are this implementation's own
//    naming; the paper does not specify concrete domain strings.
//
// --- Carried-over limitation from Phase A ---
// The OTS public key type is lattice_lrs::ots::DilithiumPublicKey, built on
// the Round 3 "Dilithium5" parameter set used as a documented stand-in for
// the "very high" parameter set of the original 2018 CRYSTALS-Dilithium
// paper that WCM actually cites; that original source is not vendored here.
// See dilithium_ots.hpp for the full rationale. This substitution does not
// affect H' itself (H' only consumes ovk as an opaque byte string), but it
// does mean "ovk" in this file's equations is a Dilithium5 public key, not
// bit-for-bit the key WCM benchmarked.

#include "lattice_lrs/commitment/commitment.hpp"
#include "lattice_lrs/ots/dilithium_ots.hpp"
#include "lattice_lrs/sampling/sampler.hpp"

namespace lattice_lrs::lrs {

// H' : {0,1}* -> R_q^n  (WCM Section 4, Setup).
//
// Output is a sampling::PolynomialVector of length parameters.n, each
// polynomial of degree parameters.degree with coefficients uniform in
// [0, parameters.q) -- the same shape as an Esgin ring_signature::PublicKey
// commitment. Deterministic: identical (parameters, ovk) always yields the
// identical output (required so KeyGen and Sign/Vrfy agree on H'(ovk)).
//
// Throws std::invalid_argument if parameters fail validate().
sampling::PolynomialVector HashOvkToPublicKeySpace(
    const commitment::Parameters& parameters,
    const ots::DilithiumPublicKey& ovk);

// pk = p_hat_k + H'(ovk)   (WCM Section 4, KeyGen).
//
// base_public_key is the untouched Esgin public key p\hat{k} (e.g.
// ring_signature::PublicKey::commitment); it is read, never mutated.
// Throws std::invalid_argument if base_public_key's length/degree/modulus
// do not match parameters, or if parameters fail validate().
sampling::PolynomialVector MaskPublicKey(
    const commitment::Parameters& parameters,
    const sampling::PolynomialVector& base_public_key,
    const ots::DilithiumPublicKey& ovk);

// p_hat_k' = pk - H'(ovk)   (WCM Section 4, Sign step 1 / Vrfy).
//
// Exact additive inverse of MaskPublicKey: for any base_public_key and ovk,
//   UnmaskPublicKey(parameters, MaskPublicKey(parameters, base_public_key,
//                    ovk), ovk) == base_public_key.
// When ovk is NOT the key that produced masked_public_key, this recovers an
// unrelated ring element by design (that is how WCM's ring transform is
// supposed to behave for the N-1 non-signing ring members); it is the
// caller's responsibility to only trust the recovered value for the
// signer's own index.
sampling::PolynomialVector UnmaskPublicKey(
    const commitment::Parameters& parameters,
    const sampling::PolynomialVector& masked_public_key,
    const ots::DilithiumPublicKey& ovk);

}  // namespace lattice_lrs::lrs
